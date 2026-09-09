"""Offline protocol/security tests; no real Google account or gateway is contacted."""

import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import crypt, jwt

from google_claude_auth import auth


class HelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.signer = crypt.RSASigner.from_string(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            key_id="test-key",
        )
        cls.certs = {
            "test-key": key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cfg = auth.Config(
            "oauth",
            "test.apps.googleusercontent.com",
            "desktop-value",
            ("example.com",),
            "",
            Path(self.temp.name) / "cache" / "client",
            360,
        )
        transport = patch.object(
            auth,
            "Request",
            return_value=lambda *args, **kwargs: SimpleNamespace(
                status=200, data=json.dumps(self.certs).encode()
            ),
        )
        transport.start()
        self.addCleanup(transport.stop)

    def claims(self, **updates):
        return {
            "iss": "https://accounts.google.com",
            "aud": self.cfg.client_id,
            "sub": "user-123",
            "email": "user@example.com",
            "email_verified": True,
            "hd": "example.com",
            "iat": int(time.time()) - 5,
            "exp": int(time.time()) + 3600,
            **updates,
        }

    def token(self, **updates):
        return jwt.encode(self.signer, self.claims(**updates)).decode()

    def seed(self, **updates):
        value = {
            "id_token": self.token(),
            "refresh_token": "refresh-old",
            "expires_at": int(time.time()) + 3600,
            "sub": "user-123",
            **updates,
        }
        with auth.locked_cache(self.cfg):
            auth.write_cache(self.cfg, value)
        return value

    def run_helper(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(auth.Config, "from_env", return_value=self.cfg),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = auth.main(list(argv))
        return result, stdout.getvalue(), stderr.getvalue()

    def login_record(self, **claims):
        return auth.cache_record(
            {"id_token": self.token(**claims), "refresh_token": "refresh-new"},
            self.claims(**claims),
        )

    def test_real_signature_validation(self):
        self.assertEqual(auth.verify_token(self.token(), self.cfg)["sub"], "user-123")

    def test_reject_invalid_identity_claims(self):
        for updates in (
            {"iss": "https://attacker.invalid"},
            {"aud": "other-client"},
            {"exp": int(time.time()) - 1},
            {"iat": int(time.time()) + 600},
            {"hd": "other.example"},
            {"hd": None},
            {"email_verified": False},
            {"sub": ""},
            {"azp": "other-client"},
        ):
            with self.subTest(updates=updates), self.assertRaises(auth.AuthError):
                auth.verify_token(self.token(**updates), self.cfg)

    def test_reject_tampered_signature(self):
        token = self.token()
        header, payload, signature = token.split(".")
        signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        with self.assertRaises(auth.AuthError):
            auth.verify_token(".".join((header, payload, signature)), self.cfg)

    def test_reject_opaque_access_token(self):
        with self.assertRaisesRegex(auth.AuthError, "ID token"):
            auth.verify_token("ya29.opaque-google-access-token", self.cfg)

    def test_nonce_and_refresh_subject(self):
        for kwargs in ({"nonce": "different"}, {"subject": "different"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(auth.AuthError):
                auth.verify_token(self.token(nonce="expected"), self.cfg, **kwargs)
        auth.verify_token(
            self.token(nonce="expected"), self.cfg, nonce="expected", subject="user-123"
        )

    def test_pinned_account(self):
        self.cfg.account = "someone@example.com"
        with self.assertRaises(auth.AuthError):
            auth.verify_token(self.token(), self.cfg)

    def test_valid_cache_avoids_refresh(self):
        cached = self.seed()
        with patch.object(auth, "token_request") as post:
            self.assertEqual(auth.oauth_token(self.cfg), cached["id_token"])
            post.assert_not_called()

    def test_refresh_preserves_refresh_token_and_drops_access_token(self):
        self.seed(expires_at=0, id_token=self.token(exp=int(time.time()) - 1))
        new_token = self.token()
        with patch.object(
            auth,
            "token_request",
            return_value={"id_token": new_token, "access_token": "ya29.do-not-use"},
        ) as post:
            self.assertEqual(auth.oauth_token(self.cfg), new_token)
            self.assertEqual(post.call_args.args[1]["grant_type"], "refresh_token")
        cached = auth.read_cache(self.cfg)
        self.assertEqual(cached["refresh_token"], "refresh-old")
        self.assertNotIn("access_token", cached)

    def test_refresh_rotation(self):
        self.seed(expires_at=0)
        with patch.object(
            auth,
            "token_request",
            return_value={"id_token": self.token(), "refresh_token": "rotated"},
        ):
            auth.oauth_token(self.cfg)
        self.assertEqual(auth.read_cache(self.cfg)["refresh_token"], "rotated")

    def test_refresh_rejects_account_change_and_keeps_cache(self):
        cached = self.seed(expires_at=0)
        with (
            patch.object(
                auth, "token_request", return_value={"id_token": self.token(sub="user-other")}
            ),
            self.assertRaises(auth.AuthError),
        ):
            auth.oauth_token(self.cfg)
        self.assertEqual(auth.read_cache(self.cfg), cached)

    def test_near_expiry_refresh_for_helper_ttl(self):
        self.seed(expires_at=int(time.time()) + 300)
        with patch.object(auth, "token_request", return_value={"id_token": self.token()}) as post:
            auth.oauth_token(self.cfg)
            post.assert_called_once()

    def test_no_fallback_to_access_token(self):
        response = SimpleNamespace(status_code=200, json=lambda: {"access_token": "opaque"})
        with (
            patch.object(auth.requests, "post", return_value=response),
            self.assertRaises(auth.AuthError),
        ):
            auth.token_request(self.cfg, {})

    def test_invalid_grant_does_not_log_response_secrets(self):
        response = SimpleNamespace(
            status_code=400,
            json=lambda: {"error": "invalid_grant", "error_description": "SECRET-REFRESH-TOKEN"},
        )
        with (
            patch.object(auth.requests, "post", return_value=response),
            self.assertRaises(auth.LoginRequired) as error,
        ):
            auth.token_request(self.cfg, {})
        self.assertNotIn("SECRET", str(error.exception))

    def test_token_request_uses_form_body_and_no_redirects(self):
        response = SimpleNamespace(status_code=200, json=lambda: {"id_token": self.token()})
        with patch.object(auth.requests, "post", return_value=response) as post:
            auth.token_request(self.cfg, {"refresh_token": "a+b&c"})
        self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "a+b&c")
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertEqual(post.call_args.args[0], "https://oauth2.googleapis.com/token")

    def test_callback_requires_state_and_unique_code(self):
        self.assertEqual(auth.callback_code("/?code=a%2Bb&state=state", "state"), "a+b")
        for path in (
            "/?code=x",
            "/?code=x&state=wrong",
            "/?code=x&state=%E3%81%82",
            "/?code=x&code=y&state=state",
            "/?code=x&state=state&state=state",
            "/?error=access_denied&state=state",
            "/favicon.ico",
        ):
            with self.subTest(path=path), self.assertRaises(auth.AuthError):
                auth.callback_code(path, "state")

    def test_auto_login_browser_flow_pkce_nonce_loopback_and_scopes(self):
        captured = {}
        client_errors = []

        def browser(url):
            params = parse_qs(urlsplit(url).query)
            captured.update(params)

            def callback():
                try:
                    redirect = params["redirect_uri"][0]
                    with urlopen(
                        redirect
                        + "?"
                        + urlencode({"code": "code+a&b", "state": params["state"][0]}),
                        timeout=5,
                    ) as response:
                        self.assertEqual(response.status, 200)
                except Exception as exc:
                    client_errors.append(exc)

            captured["thread"] = threading.Thread(target=callback)
            captured["thread"].start()

        def exchange(cfg, fields):
            captured["fields"] = fields
            return {
                "id_token": self.token(nonce=captured["nonce"][0]),
                "refresh_token": "new-refresh",
            }

        with (
            patch.object(auth.webbrowser, "open", side_effect=browser),
            patch.object(auth, "token_request", side_effect=exchange),
        ):
            code, stdout, stderr = self.run_helper("token", "--auto-login")
        self.assertEqual(code, 0, stderr)
        captured["thread"].join(timeout=5)
        self.assertFalse(client_errors)
        result = auth.read_cache(self.cfg)
        self.assertEqual(stdout, result["id_token"] + "\n")
        self.assertIn("Open on this computer", stderr)
        self.assertNotIn(result["id_token"], stderr)
        self.assertEqual(captured["scope"], ["openid email"])
        self.assertEqual(captured["access_type"], ["offline"])
        self.assertEqual(urlsplit(captured["redirect_uri"][0]).hostname, "127.0.0.1")
        self.assertEqual(captured["fields"]["code"], "code+a&b")
        expected = (
            auth.base64.urlsafe_b64encode(
                auth.hashlib.sha256(captured["fields"]["code_verifier"].encode()).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(captured["code_challenge"], [expected])
        self.assertEqual(result["refresh_token"], "new-refresh")

    def test_auto_login_reuses_valid_cache_and_refreshes_without_browser(self):
        for expiry in (int(time.time()) + 3600, 0):
            with self.subTest(expiry=expiry):
                cached = self.seed(expires_at=expiry)
                with (
                    patch.object(auth, "authorize") as login,
                    patch.object(
                        auth, "token_request", return_value={"id_token": cached["id_token"]}
                    ) as refresh,
                ):
                    code, stdout, stderr = self.run_helper("token", "--auto-login")
                self.assertEqual((code, stdout, stderr), (0, cached["id_token"] + "\n", ""))
                self.assertEqual(refresh.call_count, int(expiry == 0))
                login.assert_not_called()

    def test_auto_login_replaces_incomplete_cache_and_supports_no_browser(self):
        self.seed(refresh_token="")
        record = self.login_record()
        with patch.object(auth, "authorize", return_value=record) as login:
            code, stdout, _ = self.run_helper("--auto-login", "--no-browser")
        self.assertEqual((code, stdout), (0, record["id_token"] + "\n"))
        login.assert_called_once_with(self.cfg, True)
        self.assertEqual(auth.read_cache(self.cfg), record)

    def test_auto_login_recovers_invalid_grant_only_when_enabled(self):
        record = self.login_record()
        response = SimpleNamespace(status_code=400, json=lambda: {"error": "invalid_grant"})
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                cached = self.seed(expires_at=0)
                with (
                    patch.object(auth.requests, "post", return_value=response),
                    patch.object(auth, "authorize", return_value=record) as login,
                ):
                    code, stdout, _ = self.run_helper(
                        "token", *(["--auto-login"] if enabled else [])
                    )
                self.assertEqual(code, 0 if enabled else 1)
                self.assertEqual(stdout, record["id_token"] + "\n" if enabled else "")
                self.assertEqual(login.call_count, int(enabled))
                self.assertEqual(auth.read_cache(self.cfg), record if enabled else cached)

    def test_auto_login_does_not_hide_network_client_or_protocol_errors(self):
        cases = [
            auth.requests.ConnectionError("SECRET"),
            SimpleNamespace(status_code=200, json=lambda: {"access_token": "SECRET"}),
            SimpleNamespace(status_code=200, json=lambda: []),
        ]
        for status, error in (
            (400, "invalid_client"),
            (401, "unauthorized_client"),
            (503, "server_error"),
        ):
            cases.append(
                SimpleNamespace(status_code=status, json=lambda error=error: {"error": error})
            )
        for response in cases:
            with self.subTest(response=response):
                cached = self.seed(expires_at=0)
                kwargs = (
                    {"side_effect": response}
                    if isinstance(response, Exception)
                    else {"return_value": response}
                )
                with (
                    patch.object(auth.requests, "post", **kwargs),
                    patch.object(auth, "authorize") as login,
                ):
                    code, stdout, stderr = self.run_helper("token", "--auto-login")
                self.assertEqual((code, stdout), (1, ""))
                self.assertNotIn("SECRET", stderr)
                login.assert_not_called()
                self.assertEqual(auth.read_cache(self.cfg), cached)

    def test_auto_login_does_not_hide_token_verification_errors(self):
        for updates in ({"aud": "wrong"}, {"hd": "wrong"}, {"sub": "user-other"}):
            with self.subTest(updates=updates):
                cached = self.seed(id_token=self.token(**updates))
                with patch.object(auth, "authorize") as login:
                    code, stdout, _ = self.run_helper("token", "--auto-login")
                self.assertEqual((code, stdout), (1, ""))
                login.assert_not_called()
                self.assertEqual(auth.read_cache(self.cfg), cached)

    def test_auto_login_does_not_replace_corrupt_or_unsafe_cache(self):
        self.seed()
        path = self.cfg.cache_dir / "tokens.json"
        for content, mode in (("not json", 0o600), ("{}", 0o644)):
            with self.subTest(content=content, mode=mode):
                path.write_text(content)
                path.chmod(mode)
                with patch.object(auth, "authorize") as login:
                    code, stdout, _ = self.run_helper("token", "--auto-login")
                self.assertEqual((code, stdout), (1, ""))
                login.assert_not_called()
                self.assertEqual(path.read_text(), content)

    def test_failed_auto_login_keeps_cache_and_never_retries_login(self):
        response = SimpleNamespace(status_code=400, json=lambda: {"error": "invalid_grant"})
        for error in (
            auth.AuthError("Google login was denied"),
            auth.AuthError("Login timed out"),
            auth.LoginRequired("Authorization code rejected"),
            KeyboardInterrupt(),
        ):
            with self.subTest(error=error):
                cached = self.seed(expires_at=0)
                with (
                    patch.object(auth.requests, "post", return_value=response),
                    patch.object(auth, "authorize", side_effect=error) as login,
                ):
                    code, stdout, _ = self.run_helper("token", "--auto-login")
                self.assertEqual(
                    (code, stdout), (130 if isinstance(error, KeyboardInterrupt) else 1, "")
                )
                login.assert_called_once()
                self.assertEqual(auth.read_cache(self.cfg), cached)

    def test_auto_login_rejects_account_change_and_short_lived_tokens(self):
        response = SimpleNamespace(status_code=400, json=lambda: {"error": "invalid_grant"})
        for claims in ({"sub": "user-other"}, {"exp": int(time.time()) + 30}):
            with self.subTest(claims=claims):
                cached = self.seed(expires_at=0)
                with (
                    patch.object(auth.requests, "post", return_value=response),
                    patch.object(auth, "authorize", return_value=self.login_record(**claims)),
                ):
                    code, stdout, _ = self.run_helper("token", "--auto-login")
                self.assertEqual((code, stdout), (1, ""))
                self.assertEqual(auth.read_cache(self.cfg), cached)

    def test_auto_login_waits_for_existing_login_and_reuses_its_cache(self):
        record = self.login_record()
        with ExitStack() as owner:
            owner.enter_context(auth.locked_cache(self.cfg))

            def finish_login(_seconds):
                auth.write_cache(self.cfg, record)
                owner.close()

            # Simulate 40 seconds of browser interaction while another caller holds the lock.
            with (
                patch.object(auth.time, "monotonic", side_effect=(0, 40)),
                patch.object(auth.time, "sleep", side_effect=finish_login),
                patch.object(auth, "authorize") as login,
            ):
                code, stdout, _ = self.run_helper("token", "--auto-login")
        self.assertEqual((code, stdout), (0, record["id_token"] + "\n"))
        login.assert_not_called()

    def test_auto_login_lock_wait_is_bounded(self):
        with auth.locked_cache(self.cfg):
            with patch.object(auth.time, "monotonic", side_effect=(0, 301)):
                code, stdout, stderr = self.run_helper("token", "--auto-login")
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("Another helper/login is running", stderr)

    def test_auto_login_rejects_other_commands_and_gcloud_mode(self):
        with patch.object(auth, "authorize") as login:
            for command in ("login", "status", "logout"):
                with self.subTest(command=command), self.assertRaises(SystemExit) as error:
                    self.run_helper(command, "--auto-login")
                self.assertEqual(error.exception.code, 2)
            self.cfg.mode = "gcloud"
            code, stdout, stderr = self.run_helper("token", "--auto-login")
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("requires OAuth mode", stderr)
        login.assert_not_called()

    def test_cache_file_permissions_and_symlink_rejection(self):
        self.seed()
        path = self.cfg.cache_dir / "tokens.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.cfg.cache_dir.stat().st_mode), 0o700)
        path.chmod(0o644)
        with self.assertRaises(auth.AuthError):
            auth.read_cache(self.cfg)
        path.unlink()
        path.symlink_to(Path(self.temp.name) / "elsewhere")
        with self.assertRaises(OSError):
            auth.read_cache(self.cfg)

    def test_stdout_contains_only_id_token(self):
        cached = self.seed()
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(auth.Config, "from_env", return_value=self.cfg),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = auth.main(["token"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), cached["id_token"] + "\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_failure_has_empty_stdout(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(auth.Config, "from_env", return_value=self.cfg),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = auth.main(["token"])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("login first", stderr.getvalue())

    def test_gcloud_checks_account_audience_and_validity(self):
        self.cfg.account = "user@example.com"
        result = SimpleNamespace(returncode=0, stdout=self.token() + "\n")
        with patch.object(auth.subprocess, "run", return_value=result) as run:
            auth.gcloud_token(self.cfg)
        self.assertIn("--account=user@example.com", run.call_args.args[0])
        result.stdout = self.token(exp=int(time.time()) + 30)
        with (
            patch.object(auth.subprocess, "run", return_value=result),
            self.assertRaises(auth.AuthError),
        ):
            auth.gcloud_token(self.cfg)

    def test_reject_web_client_and_unsafe_ttl(self):
        path = Path(self.temp.name) / "client.json"
        path.write_text(json.dumps({"web": {"client_id": self.cfg.client_id}}))
        with (
            patch.dict(
                os.environ,
                {"GOOGLE_CLAUDE_CLIENT_FILE": str(path), "GOOGLE_CLAUDE_DOMAINS": "example.com"},
                clear=True,
            ),
            self.assertRaises(auth.AuthError),
        ):
            auth.Config.from_env()
        with (
            patch.dict(
                os.environ,
                {
                    "GOOGLE_CLAUDE_AUTH_MODE": "gcloud",
                    "GOOGLE_CLAUDE_DOMAINS": "example.com",
                    "GOOGLE_CLAUDE_ACCOUNT": "user@example.com",
                    "GOOGLE_CLAUDE_CLIENT_ID": self.cfg.client_id,
                    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3000000",
                },
                clear=True,
            ),
            self.assertRaises(auth.AuthError),
        ):
            auth.Config.from_env()


if __name__ == "__main__":
    unittest.main()
