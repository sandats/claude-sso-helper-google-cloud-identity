# Security

## Reporting a vulnerability

Do not include credentials or a working exploit against a real deployment in a public issue. Use the hosting platform's private reporting option when available: **Security → Advisories → Report a vulnerability** on GitHub, or a **confidential issue** on GitLab. If private reporting is unavailable, open an issue asking for a private contact channel without disclosing exploit details or affected organizations. This project does not promise a response SLA.

## Trust boundaries

- The helper runs on a user-controlled computer. Its `hd` and account checks protect the local workflow; the gateway must enforce its own authentication and authorization on every protected route/model.
- The gateway must verify the Google signature, issuer, expected Desktop client audience and expiry, and reject identities outside its approved user policy. A login-page domain hint or a user-supplied header is not authorization.
- The example maps the verified Google `sub` to an administrator-managed Kong Consumer. Register only independently verified, approved organization users. If policy requires checking `hd` on every request, implement and test that check on the gateway; the example does not configure it.
- Claude Code sends helper credentials in both `Authorization` and `x-api-key`. Ensure both are redacted from logs and removed before upstream model requests. The upstream model provider uses separate gateway-managed credentials.

## Local credentials and revocation

The helper stores ID and refresh tokens as **plaintext**, with a file lock and atomic replacement. On macOS and Linux it enforces an owned directory with mode `0700` and an owned file with mode `0600`, and refuses symlinks. On Windows it cannot check POSIX ownership or modes: it refuses symlinks and other reparse points and otherwise relies on the user profile's ACLs. It has no OS keychain integration. The user's account, machine and backups must be trusted. Keep OAuth client files and token caches outside the checkout.

`logout` removes only the current configuration's local token file. It does not revoke Google consent, already-issued ID tokens, or Claude Code's cached credential. Stop Claude Code, remove the user's gateway authorization, and revoke Google app access as appropriate. Verify authorization propagation and revocation latency in your deployment.

With `token --auto-login`, a later credential request can open a browser to authenticate again after logout or an `invalid_grant` refresh response. Automatic reauthentication retains the cached Google subject, validates the normal login claims and nonce, and saves the replacement only after success. An explicit `login` is required to intentionally switch the cached identity. Network, configuration, verification and unsafe/corrupt cache errors do not trigger automatic login. Without the flag, `token` remains noninteractive.

Google certificate retrieval happens on each verification. If retrieval fails, the helper fails without returning a credential. It never falls back to an opaque access token or an unverified JWT.

## Support scope

Security fixes target the latest code on `main`; there are no maintained older release branches. Released binaries are not code-signed; verify downloads against the release's `SHA256SUMS`. Automated tests exercise protocol and local storage behavior. They do not certify a deployment, an organization's Google policies, or Kong authorization settings. See the [setup guide](docs/SETUP-GUIDE.md#validation).
