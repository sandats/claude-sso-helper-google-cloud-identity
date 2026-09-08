"""Send three minimal inference probes, printing statuses only (never credentials).

Uses the same GOOGLE_CLAUDE_* environment as google-claude-auth.
The valid-token probe consumes a small amount of model usage.
"""

import argparse
import json
import sys
from urllib.parse import urlsplit

import requests

from . import auth


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", required=True, help="Kong URL including route prefix, without /v1/messages"
    )
    parser.add_argument("--model", required=True, help="Existing gateway model name")
    args = parser.parse_args(argv)
    url = urlsplit(args.base_url)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        parser.error("--base-url must be an HTTPS URL without credentials, query, or fragment")
    try:
        cfg = auth.Config.from_env()
        if cfg.mode == "gcloud":
            token = auth.gcloud_token(cfg)
        else:
            with auth.locked_cache(cfg):
                token = auth.oauth_token(cfg)
        head, payload, signature = token.split(".")
        bad_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        invalid = ".".join((head, payload, bad_signature))
        passed = True
        for label, credential in (
            ("missing_token", None),
            ("tampered_signature", invalid),
            ("valid_google_id_token", token),
        ):
            headers = {"anthropic-version": "2023-06-01"}
            if credential:
                headers["Authorization"] = "Bearer " + credential
            response = requests.post(
                args.base_url.rstrip("/") + "/v1/messages",
                headers=headers,
                json={
                    "model": args.model,
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": "Reply OK."}],
                },
                timeout=60,
                allow_redirects=False,
            )
            is_message = False
            if label == "valid_google_id_token" and response.status_code == 200:
                try:
                    body = response.json()
                    is_message = (
                        isinstance(body, dict)
                        and body.get("type") == "message"
                        and isinstance(body.get("content"), list)
                    )
                except ValueError:
                    pass
            ok = (
                is_message
                if label == "valid_google_id_token"
                else response.status_code in (401, 403)
            )
            print(
                json.dumps({"case": label, "http_status": response.status_code, "passed": ok}),
                flush=True,
            )
            passed = passed and ok
        return 0 if passed else 1
    except auth.AuthError as exc:
        print(f"[probe] {exc}", file=sys.stderr)
    except (OSError, requests.RequestException):
        print(
            "[probe] Local credentials or gateway unavailable; no token or response body was logged.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
