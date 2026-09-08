# Setup guide

[日本語](SETUP-GUIDE.ja.md) · [Project overview](../README.md)

This guide connects a local Claude Code installation to an existing Kong gateway using a dedicated Google Desktop OAuth client. Run shell commands from the repository root on the same macOS/Linux computer as the browser. Replace `example.com`, `user@example.com`, all paths, and the gateway URL.

## 1. Register an Internal Desktop OAuth client

In the [Google Cloud console](https://console.cloud.google.com/), select or create a project under the intended Workspace / Cloud Identity organization. A project outside the organization cannot provide its Internal audience.

In **Google Auth Platform**:

1. Configure **Branding** with an application name and contact details.
2. Set **Audience** to **Internal**, for the organization using the gateway.
3. Under **Clients**, create a client with application type **Desktop app**.
4. Download its JSON at creation and store it securely. It must contain an `installed` object with `client_id` and `client_secret`.

The helper requests `openid email`, uses Authorization Code + PKCE, and binds an ephemeral port on `127.0.0.1`. A Web application client, service-account key, or SAML configuration is not a substitute. Renaming JSON keys does not change the registered client type. See [Google's native application flow](https://developers.google.com/identity/protocols/oauth2/native-app).

If organization policies block the app, have the Google administrator review the **client ID** in [app access control](https://support.google.com/a/answer/7281227?hl=en). The helper does not require Directory API permissions or a service-account key. Desktop clients cannot keep a distributed client secret confidential; their client secret is not proof that a request comes from an approved user.

## 2. Install and log in

Keep the downloaded client file outside the checkout:

```bash
mkdir -p "$HOME/.config/claude-google-sso"
chmod 700 "$HOME/.config/claude-google-sso"
install -m 600 '/absolute/path/downloaded-client.json' \
  "$HOME/.config/claude-google-sso/client_secret_desktop.json"

python3 -m venv .venv
.venv/bin/python -m pip install .

export GOOGLE_CLAUDE_AUTH_MODE='oauth'
unset GOOGLE_CLAUDE_CLIENT_ID
export GOOGLE_CLAUDE_CLIENT_FILE="$HOME/.config/claude-google-sso/client_secret_desktop.json"
export GOOGLE_CLAUDE_DOMAINS='example.com'
export GOOGLE_CLAUDE_ACCOUNT='user@example.com'
export CLAUDE_CODE_API_KEY_HELPER_TTL_MS='300000'

.venv/bin/google-claude-auth login
.venv/bin/google-claude-auth status
```

Select the intended organization account and complete Google's login/consent flow. Login waits up to three minutes. If the browser does not open, open the printed URL on the same computer. `--no-browser` does not enable remote login.

`status` verifies and displays `iss`, `aud`, `sub`, `email`, `hd` and `exp`. Confirm that `aud` matches `installed.client_id`, and that the account and hosted domain are correct. Treat the output as personal identity data. If you pin an account here, also pin it in Claude Code settings.

## 3. Configure gateway authentication and authorization

[kongctl-oidc.example.yaml](../examples/kongctl-oidc.example.yaml) is a **partial Kong AI Gateway v2 declaration**, with no provider or model definitions. Merge it into your existing declaration; it is not a standalone deployment file. Review a diff using your existing deployment workflow before applying it.

Configure the administrator-controlled gateway to:

- Use Google as issuer, verify signatures and expiry, and require the dedicated Desktop client ID in `audience_required` as well as `client_id`.
- Use `auth_methods: [bearer]` and `consumer_optional: false`.
- Resolve the signed `sub` through `consumer_claims: [[sub]]` and `consumer_by: [custom_id]`. Register only approved users after independently verifying their Google identity and organization membership.
- Attach the auth strategy and group ACLs to **every protected model**. Keep provider credentials and existing model/rate-limit policies on the gateway.
- Remove both incoming `Authorization` and `x-api-key` credentials before forwarding upstream, and redact them from access/error logs. Verify the behavior of `hide_credentials` and any additional header rules in your setup.

A user's local `status` output is useful for enrollment, but an unverified copy of that output is not sufficient identity proof for the administrator. If migrating an existing email-based Consumer mapping, migrate its identifiers and claims together or use a separate strategy during transition.

The example relies on an Internal OAuth app, the expected audience, and an approved `sub` allowlist. It does **not** implement a gateway check of `hd` on every request. Add trusted server-side validation if your policy requires that check. A login-page `hd` hint is not access control; see [Google's ID-token validation requirements](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken).

Schema fields differ between AI Gateway v2 and the conventional OIDC plugin. Inspect the version installed in your environment:

```bash
kongctl explain ai_gateways.auth_strategies.config --extended
kongctl explain ai_gateways.consumers --extended
kongctl explain ai_gateways.consumer_groups --extended
```

### Google Groups

The example uses static Kong Consumer Group membership. For Google Groups integration, build an administrator-side Directory API or Cloud Identity API sync job that updates gateway membership. It must handle removals, pagination, nested membership policy, and failed synchronization. That integration is not included. Do not add a `groups` field to Google's signed token or trust group headers supplied by a user.

## 4. Configure Claude Code

Merge [claude-settings.example.json](../examples/claude-settings.example.json) into `~/.claude/settings.json`, or the appropriate organization-managed settings. Preserve unrelated settings and existing model choices.

- Replace the `apiKeyHelper` path with the absolute path to the installed `.venv/bin/google-claude-auth` command. Keep the quoting if the path contains spaces.
- Set the absolute path to the same client JSON used for login. Do not depend on `$HOME` interpolation inside a JSON `env` value.
- Use the same mode, account, domains, helper TTL and optional cache directory as the login shell. Different settings can select a different cache.
- Set `ANTHROPIC_BASE_URL` to the gateway route prefix, without `/v1/messages`. For example, `https://gateway.example.com/v1/claude` makes Messages requests to `https://gateway.example.com/v1/claude/v1/messages`.
- Select a model name served by your gateway using its existing Claude Code model settings. Use the gateway's Anthropic API interface.

Remove conflicting static credentials from shell and settings, then start Claude Code:

```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
claude
```

Send a short prompt and check `/status` for the gateway and credential source. The helper's `token` command stays noninteractive. If it requests a new login, run `login` from a terminal with the same configuration and restart Claude Code. See [Claude Code's gateway configuration](https://code.claude.com/docs/en/llm-gateway-connect).

## Validation

Run offline tests first:

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -v
```

After login and gateway configuration, an optional probe makes three real requests. The valid request consumes model usage with up to eight output tokens. It prints only case names, HTTP statuses and pass/fail results:

```bash
.venv/bin/google-claude-verify-gateway \
  --base-url 'https://gateway.example.com/v1/claude' \
  --model 'YOUR-GATEWAY-MODEL'
```

| Case | Expected result |
| --- | --- |
| Missing credential | HTTP 401 or 403 |
| Modified JWT signature | HTTP 401 or 403 |
| Valid Google ID token | HTTP 200 with an Anthropic Messages response |

Before production use, also verify dedicated-client refresh, actual Claude Code startup, and gateway rejection of wrong audience, expired tokens, unregistered users and users outside policy. Test model ACLs, membership changes, removal of user access, and credential stripping/redaction. The three probes do not cover those conditions; local helper rejection does not prove gateway rejection.

## Optional: gcloud development compatibility

The `gcloud` mode uses a pre-existing user login, requires an explicit account and expected audience, and applies the same local identity checks. It does not exercise the dedicated Desktop client flow. Google describes generic gcloud ID tokens as a [development option](https://docs.cloud.google.com/docs/authentication/get-id-token#generic-dev).

```bash
gcloud auth login user@example.com
export GOOGLE_CLAUDE_AUTH_MODE='gcloud'
export GOOGLE_CLAUDE_ACCOUNT='user@example.com'
export GOOGLE_CLAUDE_DOMAINS='example.com'
export GOOGLE_CLAUDE_CLIENT_ID='YOUR-VERIFIED-GCLOUD-AUDIENCE.apps.googleusercontent.com'
export CLAUDE_CODE_API_KEY_HELPER_TTL_MS='0'
.venv/bin/google-claude-auth status
```

Obtain the expected audience from your reviewed gcloud setup; do not trust an arbitrary token's decoded payload to configure the gateway. Shared gcloud audiences alone cannot identify users who consented to your dedicated app. The helper does not control gcloud's refresh timing and rejects near-expiry tokens. Manage login/logout with gcloud. Use `oauth` mode for the primary setup.

## Troubleshooting and logout

| Symptom | Check |
| --- | --- |
| Internal unavailable / `org_internal` | Project organization and user's organization |
| Invalid Desktop JSON | Download a Desktop app JSON with an `installed` section |
| Client ID differs from JSON | Unset a leftover `GOOGLE_CLAUDE_CLIENT_ID` in OAuth mode |
| App blocked / `admin_policy_enforced` | Administrator approval for the client ID |
| Localhost callback fails | Same computer/browser, active three-minute wait, loopback allowed |
| Domain/account rejection | Signed `hd`, intended organization account, configured allowlist |
| `invalid_grant` | Repeat `login`; check consent and administrator policy |
| `status` succeeds, gateway rejects | Audience, deployed auth strategy, Consumer identifier, model ACL |
| Claude Code has no cached login | Match terminal/settings configuration and absolute paths |
| Google verification unavailable | Network access to Google's certificate endpoint and local clock |

```bash
.venv/bin/google-claude-auth logout
```

This removes only the current configuration's local cache. Stop Claude Code and remove gateway access for user offboarding; Google consent and issued tokens are not revoked by this command. See [SECURITY.md](../SECURITY.md).
