"""Google user ID-token helper for Claude Code -> Kong (macOS/Linux, Python 3.10+).

Install the project. Configure GOOGLE_CLAUDE_CLIENT_FILE (Desktop OAuth JSON)
and GOOGLE_CLAUDE_DOMAINS, then run `login` once and use `token` in apiKeyHelper.
Only `token` writes a credential to stdout. See README.md for the gateway policy.
"""

import argparse
import base64
import fcntl
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import webbrowser
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from google.auth import exceptions as google_errors
from google.auth.transport.requests import Request
from google.oauth2 import id_token

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


class AuthError(Exception):
    """Safe, credential-free error text for stderr."""


@dataclass
class Config:
    mode: str
    client_id: str
    client_secret: str
    domains: tuple
    account: str
    cache_dir: Path
    min_validity: float

    @classmethod
    def from_env(cls):
        mode = os.environ.get("GOOGLE_CLAUDE_AUTH_MODE", "oauth")
        if mode not in ("oauth", "gcloud"):
            raise AuthError("GOOGLE_CLAUDE_AUTH_MODE must be oauth or gcloud.")
        domains = tuple(
            sorted(
                {
                    d.strip().lower()
                    for d in os.environ.get("GOOGLE_CLAUDE_DOMAINS", "").split(",")
                    if d.strip()
                }
            )
        )
        if not domains or any(d == "*" or "/" in d or "@" in d for d in domains):
            raise AuthError("Set GOOGLE_CLAUDE_DOMAINS to the allowed hosted domains.")
        client_id = os.environ.get("GOOGLE_CLAUDE_CLIENT_ID", "")
        client_secret = ""
        if mode == "oauth":
            filename = os.environ.get("GOOGLE_CLAUDE_CLIENT_FILE", "")
            if not filename:
                raise AuthError(
                    "Set GOOGLE_CLAUDE_CLIENT_FILE to a Desktop OAuth client JSON file."
                )
            try:
                data = json.loads(Path(filename).expanduser().read_text())
                installed = data["installed"]
                file_id = installed["client_id"]
                client_secret = installed["client_secret"]
            except (OSError, ValueError, KeyError, TypeError):
                raise AuthError(
                    "Cannot read a valid Desktop OAuth client JSON (installed section)."
                ) from None
            if client_id and client_id != file_id:
                raise AuthError("GOOGLE_CLAUDE_CLIENT_ID differs from the client JSON.")
            client_id = file_id
        if not isinstance(client_id, str) or not client_id.endswith(".apps.googleusercontent.com"):
            raise AuthError("Set a Google OAuth client ID as the expected audience.")
        if not isinstance(client_secret, str):
            raise AuthError("Invalid client_secret in client JSON.")
        account = os.environ.get("GOOGLE_CLAUDE_ACCOUNT", "").strip().lower()
        if mode == "gcloud" and not account:
            raise AuthError("Set GOOGLE_CLAUDE_ACCOUNT explicitly for gcloud mode.")
        try:
            ttl = int(os.environ.get("CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "300000"))
        except ValueError:
            raise AuthError("CLAUDE_CODE_API_KEY_HELPER_TTL_MS must be an integer.") from None
        if not 0 <= ttl <= 300000:
            raise AuthError("Use a helper TTL between 0 and 300000 ms (at most five minutes).")
        key = hashlib.sha256(json.dumps([mode, client_id, domains, account]).encode()).hexdigest()[
            :24
        ]
        root = Path(os.environ.get("GOOGLE_CLAUDE_CACHE_DIR", "~/.claude/google-sso")).expanduser()
        return cls(mode, client_id, client_secret, domains, account, root / key, ttl / 1000 + 60)


def verify_token(token, cfg, nonce=None, subject=None):
    if not isinstance(token, str) or token.count(".") != 2 or any(c.isspace() for c in token):
        raise AuthError("Expected a Google ID token (JWT), not an access token.")
    try:
        # Google's library verifies the signature, iss, aud, iat and exp.
        # Fixed Google certificate endpoint: never trust a token-supplied jku.
        with requests.Session() as session:
            transport = Request(session=session)

            def bounded_request(*args, **kwargs):
                return transport(*args, **{**kwargs, "timeout": 20})

            claims = id_token.verify_oauth2_token(token, bounded_request, audience=cfg.client_id)
    except (
        ValueError,
        KeyError,
        TypeError,
        google_errors.GoogleAuthError,
        requests.RequestException,
    ):
        raise AuthError(
            "Google ID-token signature/issuer/audience/expiry verification failed, or Google is unreachable."
        ) from None
    if claims.get("hd") not in cfg.domains:
        raise AuthError("The signed hd claim is missing or outside the allowed domains.")
    if claims.get("email_verified") is not True or not claims.get("email"):
        raise AuthError("A verified Google account email is required.")
    if cfg.account and claims["email"].lower() != cfg.account:
        raise AuthError("The Google account differs from GOOGLE_CLAUDE_ACCOUNT.")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise AuthError("Missing Google subject.")
    if claims.get("azp", cfg.client_id) != cfg.client_id:
        raise AuthError("Unexpected authorized party (azp).")
    if nonce is not None and claims.get("nonce") != nonce:
        raise AuthError("OIDC nonce mismatch.")
    if subject is not None and claims["sub"] != subject:
        raise AuthError("Account changed during refresh; run login again.")
    if not isinstance(claims.get("exp"), (int, float)):
        raise AuthError("Missing token expiry.")
    return claims


def token_request(cfg, fields):
    body = {"client_id": cfg.client_id, "client_secret": cfg.client_secret, **fields}
    try:
        # Do not follow redirects carrying client or refresh credentials.
        response = requests.post(TOKEN_URL, data=body, timeout=30, allow_redirects=False)
        data = response.json()
    except (requests.RequestException, ValueError):
        raise AuthError(
            "Google token endpoint unavailable or returned invalid JSON; retry later."
        ) from None
    if not isinstance(data, dict):
        raise AuthError("Google returned an invalid token response.")
    if response.status_code != 200 or data.get("error"):
        if data.get("error") == "invalid_grant":
            raise AuthError("Google requires a new login (invalid_grant); run login again.")
        if data.get("error") in ("invalid_client", "unauthorized_client"):
            raise AuthError(
                "Google rejected the OAuth client; check the Desktop client JSON and admin policy."
            )
        raise AuthError(
            f"Google token request failed (HTTP {response.status_code}); check OAuth/admin configuration."
        )
    if not data.get("id_token"):
        raise AuthError("No id_token returned. Authorize with openid email; run login again.")
    return data


def callback_code(path, expected_state):
    parsed = urlsplit(path)
    if parsed.path != "/":
        raise AuthError("Unknown callback path.")
    params = parse_qs(parsed.query)
    states = params.get("state", [])
    if len(states) != 1 or not secrets.compare_digest(states[0].encode(), expected_state.encode()):
        raise AuthError("OAuth state mismatch.")
    if params.get("error"):
        raise AuthError("Google login was denied; check consent and administrator policy.")
    codes = params.get("code", [])
    if len(codes) != 1 or not codes[0]:
        raise AuthError("Missing or ambiguous authorization code.")
    return codes[0]


def authorize(cfg, no_browser=False):
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    outcome = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Callback URLs contain authorization codes: never log them.

        def do_GET(self):
            try:
                code = callback_code(self.path, state)
            except AuthError as exc:
                status, body = 400, b"Login callback rejected. Return to your terminal."
                # Unrelated localhost requests must not terminate the real login.
                params = parse_qs(urlsplit(self.path).query)
                if params.get("state") == [state] and params.get("error"):
                    outcome["error"] = exc
            else:
                outcome["code"] = code
                status, body = (
                    200,
                    b"Login response received. Close this tab and return to your terminal.",
                )
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class LoopbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address

    # Bind BEFORE opening the browser; ephemeral IPv4 loopback port, no LAN listener.
    with LoopbackServer(("127.0.0.1", 0), Callback) as server:
        server.timeout = 1
        redirect_uri = f"http://127.0.0.1:{server.server_port}/"
        url = (
            AUTH_URL
            + "?"
            + urlencode(
                {
                    "client_id": cfg.client_id,
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": "openid email",
                    "access_type": "offline",
                    "prompt": "consent select_account",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                    "nonce": nonce,
                    "hd": cfg.domains[0] if len(cfg.domains) == 1 else "*",
                    **({"login_hint": cfg.account} if cfg.account else {}),
                }
            )
        )
        print("[google-auth] Open on this computer:\n" + url, file=sys.stderr)
        if not no_browser:
            with redirect_stdout(sys.stderr):
                webbrowser.open(url)
        deadline = time.monotonic() + 180
        while not outcome and time.monotonic() < deadline:
            server.handle_request()
    if "error" in outcome:
        raise outcome["error"]
    if "code" not in outcome:
        raise AuthError("Login timed out after 180 seconds; run login again.")
    data = token_request(
        cfg,
        {
            "grant_type": "authorization_code",
            "code": outcome["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    claims = verify_token(data["id_token"], cfg, nonce=nonce)
    if not data.get("refresh_token"):
        raise AuthError(
            "Google did not return a refresh token; check offline consent and run login again."
        )
    return cache_record(data, claims)


def cache_record(data, claims, previous=None):
    refresh = data.get("refresh_token") or (previous or {}).get("refresh_token")
    if not isinstance(refresh, str) or not refresh:
        raise AuthError("No refresh token available; run login again.")
    # Opaque Google API access tokens are deliberately neither stored nor emitted.
    return {
        "id_token": data["id_token"],
        "refresh_token": refresh,
        "sub": claims["sub"],
        "expires_at": claims["exp"],
    }


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise AuthError("Cache directory must be an owned directory, not a symlink.")
    path.chmod(0o700)


@contextmanager
def locked_cache(cfg):
    private_directory(cfg.cache_dir.parent)
    private_directory(cfg.cache_dir)
    fd = os.open(cfg.cache_dir / "auth.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        deadline = time.monotonic() + 35
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AuthError(
                        "Another helper/login is running; retry after it completes."
                    ) from None
                time.sleep(0.1)
        yield


def read_cache(cfg):
    path = cfg.cache_dir / "tokens.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise AuthError("Token cache must be an owned regular file with mode 0600.")
        try:
            value = json.load(stream)
        except ValueError:
            raise AuthError("Invalid token cache; run login to replace it.") from None
    if not isinstance(value, dict):
        raise AuthError("Invalid token cache; run login to replace it.")
    return value


def write_cache(cfg, value):
    fd, name = tempfile.mkstemp(prefix=".tokens-", dir=cfg.cache_dir)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, cfg.cache_dir / "tokens.json")
    finally:
        if os.path.exists(name):
            os.unlink(name)


def oauth_token(cfg):
    cached = read_cache(cfg)
    if not cached.get("id_token") or not cached.get("refresh_token") or not cached.get("sub"):
        raise AuthError("No complete login cached; run login first.")
    # Cached expiry is only a refresh hint. Never output a token without verification.
    expiry = cached.get("expires_at", 0)
    if isinstance(expiry, (int, float)) and expiry > time.time() + cfg.min_validity:
        claims = verify_token(cached["id_token"], cfg, subject=cached["sub"])
        if claims["exp"] > time.time() + cfg.min_validity:
            return cached["id_token"]
    data = token_request(
        cfg, {"grant_type": "refresh_token", "refresh_token": cached["refresh_token"]}
    )
    claims = verify_token(data["id_token"], cfg, subject=cached["sub"])
    if claims["exp"] <= time.time() + cfg.min_validity:
        raise AuthError("Refreshed ID token expires too soon for the helper TTL.")
    write_cache(cfg, cache_record(data, claims, cached))
    return data["id_token"]


def gcloud_token(cfg):
    try:
        result = subprocess.run(
            [
                "gcloud",
                "auth",
                "print-identity-token",
                f"--account={cfg.account}",
                "--quiet",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise AuthError(
            "Cannot execute gcloud; install it and run gcloud auth login first."
        ) from None
    if result.returncode:
        raise AuthError("gcloud failed; run gcloud auth login for GOOGLE_CLAUDE_ACCOUNT.")
    token = result.stdout.strip()
    claims = verify_token(token, cfg)
    if claims["exp"] <= time.time() + cfg.min_validity:
        raise AuthError(
            "gcloud returned a near-expiry token; use TTL=0 for PoC or the dedicated OAuth mode."
        )
    return token


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("login", "token", "status", "logout"), nargs="?", default="token"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print login URL; still requires local loopback callback",
    )
    args = parser.parse_args(argv)
    try:
        cfg = Config.from_env()
        if cfg.mode == "gcloud":
            if args.command not in ("token", "status"):
                raise AuthError("gcloud mode: manage login/logout with gcloud auth commands.")
            token = gcloud_token(cfg)
        else:
            with locked_cache(cfg):
                if args.command == "login":
                    write_cache(cfg, authorize(cfg, args.no_browser))
                    print(
                        "[google-auth] Login saved; apiKeyHelper can now run token.",
                        file=sys.stderr,
                    )
                    return 0
                if args.command == "logout":
                    (cfg.cache_dir / "tokens.json").unlink(missing_ok=True)
                    print(
                        "[google-auth] Local cache removed. Google authorization was not revoked.",
                        file=sys.stderr,
                    )
                    return 0
                token = oauth_token(cfg)
        if args.command == "token":
            print(token)
        else:
            claims = verify_token(token, cfg)
            print(
                json.dumps(
                    {k: claims.get(k) for k in ("iss", "aud", "sub", "email", "hd", "exp")},
                    indent=2,
                )
            )
        return 0
    except AuthError as exc:
        print(f"[google-auth] {exc}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "[google-auth] Local file, browser, or callback operation failed; check permissions and retry.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("[google-auth] Cancelled.", file=sys.stderr)
        return 130
