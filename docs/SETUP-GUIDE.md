# Setup guide

[日本語](SETUP-GUIDE.ja.md) · [Project overview](../README.md)

This guide connects a local Claude Code installation to an existing Kong gateway using a dedicated Google Desktop OAuth client. Run shell commands from the repository root on the same macOS/Linux computer as the browser. Replace `example.com`, `user@example.com`, all paths, and the gateway URL.

## Prerequisites

Use macOS or Linux with Python 3.10+, a browser on the same computer, and Claude Code with `apiKeyHelper` support. You need a Google Cloud project under the intended Workspace / Cloud Identity organization and an Internal Desktop OAuth client, created in section 1. Your Kong deployment must support Google OIDC authentication and user authorization; the example targets AI Gateway v2. The conventional [Kong OIDC plugin requires Enterprise](https://developer.konghq.com/plugins/openid-connect/). This project does not include gateway or model access entitlements.

**An existing, configured CP, Model, and Provider are required before starting this procedure.** The gateway administrator must confirm the following:

| Existing resource | Required state |
| --- | --- |
| CP (Control Plane) | A Konnect AI Gateway v2 CP exists, and the administrator can read and update its configuration in the intended organization and region |
| Provider (AI Model Provider) | The CP contains an upstream LLM provider with a configured endpoint, valid credentials, and access to the intended model |
| Model (AI Model) | The CP contains the intended model linked to that Provider; its client-facing model name is known |
| DP (Data Plane) and endpoint | A running DP is connected to the CP and reachable over HTTPS from the user's computer; model requests using the Anthropic Messages API format have been verified with the existing authentication method |

This guide adds Google SSO to that existing deployment. It does not provision the CP, Model, Provider, or DP. If they do not exist, complete [Kong AI Gateway setup](https://developer.konghq.com/ai-gateway/) first. The administrator supplies the existing kongctl YAML for section 3 and gives users the **gateway base URL and available model names** for section 4. The base URL serves model requests; it is not the Konnect management API URL.

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

The **gateway administrator** performs this section. Prepare the CP, Model, Provider, and running DP listed in [Prerequisites](#prerequisites), then install [kongctl](https://developer.konghq.com/kongctl/) and configure access to the intended Konnect organization and region. You need the existing kongctl YAML file that manages the gateway. [kongctl-oidc.example.yaml](../examples/kongctl-oidc.example.yaml) is a **partial declaration** to merge into that file; it does not create providers or models.

### 3.1. Understand the resources

Kong uses the following settings to authenticate the user and decide whether they may access a model.

| Setting | Purpose | Name in the example |
| --- | --- | --- |
| Auth strategy | Verify the Google ID token's signature, expiry, and intended application | `google-desktop-oidc` |
| Consumer | Identify an approved user by registering their Google `sub` as `custom_id` | `google-user-example` |
| Consumer Group | Collect Consumers into a group that can be granted model access | `claude-standard-users` |
| Model `access` | Select the authentication strategy and allowed groups | Configure on each protected existing model |

The example resolves the Google ID token's `sub` to a registered Consumer, then checks that Consumer's membership in an allowed group. Creating the strategy alone does not protect a model; attach it in section 3.3.

### 3.2. Set environment variables

Set these variables in the terminal where you will run kongctl. Replace the sample values below with your own.

| Variable | Value and source |
| --- | --- |
| `CLIENT_ID` | `installed.client_id` in the Desktop OAuth client JSON from section 1; it must match `aud` in section 2's `status` output |
| `GOOGLE_USER_SUB` | The approved user's Google `sub`, available from `status`; the administrator must verify identity and organization membership before enrollment |
| `OIDC_CACHE_TOKENS_SALT` | Stable value for Kong's OIDC cache; generate once for a new strategy and reuse on subsequent applies |
| `KONG_CONFIG` | Path to the existing kongctl YAML file managing the target gateway; edit this file in section 3.3 |

```bash
export CLIENT_ID='123456789012-example.apps.googleusercontent.com'
export GOOGLE_USER_SUB='123456789012345678901'
export KONG_CONFIG='/absolute/path/to/your-existing-kongctl.yaml'

# Generate only for a new strategy; save in administrator storage and reuse next time
export OIDC_CACHE_TOKENS_SALT="$(openssl rand -hex 32)"
```

AI Gateway v2 requires `cache_tokens_salt` for OIDC auth strategies to derive cache keys. This is separate from Google's client secret and reads `!env OIDC_CACHE_TOKENS_SALT`. When updating an existing strategy, restore its saved value instead of generating another. See [Kong AI Auth Strategies](https://developer.konghq.com/ai-gateway/entities/ai-auth-strategy/).

The example uses `!env`, so **you do not need to replace client IDs or `custom_id` in the YAML**. `client_id` identifies the OAuth client, while `audience_required` specifies the accepted ID token audience. Both use the same `CLIENT_ID` in this setup.

```yaml
client_id:
  - !env CLIENT_ID
audience_required:
  - !env CLIENT_ID
```

The Consumer's `custom_id` also reads `!env GOOGLE_USER_SUB`. These variables are for kongctl; you do not need to add them to Claude Code's `settings.json`. Set them again when using another terminal or CI environment. Unset `!env` variables are errors, but empty values are allowed, so section 3.4 also checks for empty values. See [kongctl environment variable references](https://developer.konghq.com/kongctl/declarative/#loading-values-from-environment-variables).

Register the Consumer only after the administrator independently verifies the user's Google signature and organization membership. An unverified copy of a user's `status` output is not sufficient identity proof.

### 3.3. Merge into the existing gateway configuration

Open the file specified by `KONG_CONFIG` in an editor. A `ref` identifies a resource within the YAML, and `!ref` refers to that resource; it is distinct from a Konnect-assigned UUID.

1. Find the target gateway's `ref` under the existing `ai_gateways` list. Replace every `YOUR-EXISTING-GATEWAY-REF` in the example with that value.
2. Add the example's `auth_strategies`, `consumers`, and `consumer_groups` entries under that gateway. If a key already exists, append entries to its list; if an entry with the same `ref` exists, update that entry. Do not paste a duplicate `ai_gateways:` key or gateway. Preserve existing models, providers, upstream credentials, and policies.
3. Merge the following `access` block into **every protected model** under that gateway's `models`. If `access` already exists, review its strategies and allowed groups and edit it to grant the intended access.

```yaml
# Add at the same indentation as the existing model's ref and name
access:
  auth_strategies:
    - !ref google-desktop-oidc
  acls:
    allow:
      - claude-standard-users
```

`acls.allow` lists the names of Consumer Groups allowed to access the model. The example adds `google-user-example` to `claude-standard-users`. To enroll more users, add a Consumer with a distinct `ref`, `name`, and environment variable for each user's `sub`, and add its reference to the group's `consumers` list. Changing `GOOGLE_USER_SUB` to another person's value for the same Consumer replaces the existing user's registration.

### 3.4. Preview and apply

Use the terminal where you set the variables in section 3.2. If you have not run `kongctl login`, log in with the target environment's configuration first. If your normal commands use `--profile` or `--region`, use the same options for both the diff and apply commands.

```bash
kongctl login

# Stop and correct any unset or empty value before continuing
: "${CLIENT_ID:?Set CLIENT_ID to the Desktop OAuth client ID}"
: "${GOOGLE_USER_SUB:?Set GOOGLE_USER_SUB to the approved Google user sub}"
: "${OIDC_CACHE_TOKENS_SALT:?Set OIDC_CACHE_TOKENS_SALT to the saved salt}"
: "${KONG_CONFIG:?Set KONG_CONFIG to the merged gateway YAML path}"

kongctl diff --mode apply -f "$KONG_CONFIG"
```

Check that the diff includes the intended strategy, Consumer, group membership, and each model's `access`. Confirm the target gateway and changes to existing settings. Then apply with the same environment values:

```bash
kongctl apply -f "$KONG_CONFIG"
```

Review the changes shown by `apply` and enter `yes` at its confirmation prompt. The input is **the existing configuration file edited in section 3.3**, not the unmerged example by itself. This workflow uses `apply`, which creates and updates resources; `sync` also handles deletion. See [kongctl preview and apply](https://developer.konghq.com/kongctl/declarative/#create-your-first-configuration).

### 3.5. Check authentication and authorization behavior

- `auth_methods: [bearer]` accepts Bearer tokens. `consumer_claims: [[sub]]` and `consumer_by: [custom_id]` identify the user, and `consumer_optional: false` rejects users without a matching registered Consumer.
- Remove both incoming `Authorization` and `x-api-key` credentials before forwarding upstream, and redact them from access/error logs. Verify the behavior of `hide_credentials` and any additional header rules in your setup.
- If migrating an existing email-based Consumer mapping, migrate its identifiers and claims together. OIDC models within the same AI Gateway must reference the same auth strategy, so plan updates to an existing OIDC strategy and model references together. See [Kong AI Auth Strategies](https://developer.konghq.com/ai-gateway/entities/ai-auth-strategy/).

**Local helper checks do not replace gateway authorization.** Users can send HTTP requests without the helper. The example relies on an Internal OAuth app, the expected audience, and an approved `sub` allowlist. It does not implement a gateway check of `hd` on every request. Add trusted server-side validation if your policy requires that check. A login-page `hd` hint is not access control; see [Google's ID-token validation requirements](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken).

Schema fields differ between AI Gateway v2 and the conventional OIDC plugin. Inspect the version installed in your environment with these commands, then follow the Validation section to test connectivity and rejection cases:

```bash
kongctl explain ai_gateways.auth_strategies.config --extended
kongctl explain ai_gateways.consumers --extended
kongctl explain ai_gateways.consumer_groups --extended
```

### Google Groups

The example's `claude-standard-users` is a **group managed in Kong**. Giving it the same name as a Google Group does not synchronize membership. You can initially grant approved users access by registering their Consumers in this group as shown in section 3.3, without configuring Google Groups.

For Google Groups integration, build an administrator-side Directory API or Cloud Identity API sync job that updates gateway membership. It must handle removals, pagination, nested membership policy, and failed synchronization. That integration is not included. Do not add a `groups` field to Google's signed token or trust group headers supplied by a user.

## 4. Configure Claude Code

Perform this section on **the user's Claude Code computer**. Use [claude-settings.example.json](../examples/claude-settings.example.json) as the template for the user settings file, `~/.claude/settings.json`. Editing the example inside the repository alone does not configure Claude Code. If your organization manages settings centrally, have the administrator deploy the same keys through managed settings. See [Claude Code settings files](https://code.claude.com/docs/en/settings).

### 4.1. Prepare the settings file

Run from the repository root on the computer used for section 2. This backs up an existing settings file with a timestamp, or copies the example only when no settings file exists.

```bash
mkdir -p "$HOME/.claude"
if [ -f "$HOME/.claude/settings.json" ]; then
  cp -p "$HOME/.claude/settings.json" \
    "$HOME/.claude/settings.json.backup-$(date +%Y%m%d-%H%M%S)"
else
  cp examples/claude-settings.example.json "$HOME/.claude/settings.json"
fi
```

Open `~/.claude/settings.json` in your editor. For an existing file, add or update `apiKeyHelper` from the example and merge the example's individual `env` keys into the existing `env` object. Keep existing model settings, `permissions`, `hooks`, and unrelated environment variables. Do not replace the entire `env` object or duplicate keys.

### 4.2. Replace the example values

Write every value inside `env` as a JSON string. Replace the paths, URL, domain, and account using the following table.

| Key to edit | Value and source |
| --- | --- |
| `apiKeyHelper` | Absolute path to the `.venv/bin/google-claude-auth` command installed in section 2, followed by `token`; preserve the escaped quotes (`\"`) around the path |
| `env.ANTHROPIC_BASE_URL` | HTTPS base URL supplied by the gateway administrator, such as `https://gateway.example.com/v1/claude`; do not append `/v1/messages` |
| `env.GOOGLE_CLAUDE_CLIENT_FILE` | Absolute path to the Desktop client JSON used in section 2, such as `/Users/example/.config/claude-google-sso/client_secret_desktop.json` |
| `env.GOOGLE_CLAUDE_DOMAINS` | Same organization domain as section 2's `GOOGLE_CLAUDE_DOMAINS`, such as `example.com` |
| `env.GOOGLE_CLAUDE_ACCOUNT` | Account used in section 2, such as `user@example.com`; remove this key if you did not pin an account there |
| `env.GOOGLE_CLAUDE_AUTH_MODE` | Keep `"oauth"` for the normal setup |
| `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS` | Same value as section 2; normally keep `"300000"` (five minutes) |

To find the helper and client JSON paths, run these commands in the terminal with section 2's environment variables:

```bash
printf '%s/.venv/bin/google-claude-auth\n' "$(pwd -P)"
printf '%s\n' "$GOOGLE_CLAUDE_CLIENT_FILE"
```

Use actual absolute paths in JSON; do not assume `$HOME` or `~` expands as it does in a shell. `GOOGLE_CLAUDE_CLIENT_FILE` points to the OAuth client JSON, not the token cache. If you set an optional `GOOGLE_CLAUDE_CACHE_DIR` in section 2, add the same absolute path to `env`. Match mode, client, account, domains, and cache directory to the initial login so the helper selects the same token cache.

For example, with a macOS checkout at `/Users/example/projects/claude-sso-helper-google-cloud-identity`, the settings for this integration look like this. Adapt the values to your computer and keep any existing settings alongside these keys.

```json
{
  "apiKeyHelper": "\"/Users/example/projects/claude-sso-helper-google-cloud-identity/.venv/bin/google-claude-auth\" token",
  "env": {
    "ANTHROPIC_BASE_URL": "https://gateway.example.com/v1/claude",
    "GOOGLE_CLAUDE_AUTH_MODE": "oauth",
    "GOOGLE_CLAUDE_CLIENT_FILE": "/Users/example/.config/claude-google-sso/client_secret_desktop.json",
    "GOOGLE_CLAUDE_DOMAINS": "example.com",
    "GOOGLE_CLAUDE_ACCOUNT": "user@example.com",
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "300000"
  }
}
```

Section 3's `CLIENT_ID`, `GOOGLE_USER_SUB`, and `OIDC_CACHE_TOKENS_SALT` are for kongctl and do not belong in this JSON. You do not need to paste a Provider API key or Google ID token into it; `apiKeyHelper` obtains the credential.

### 4.3. Validate JSON and start Claude Code

Save the file and check its JSON syntax. Success produces no output; correct the reported location if validation fails. JSON does not allow comments or trailing commas.

```bash
.venv/bin/python -m json.tool "$HOME/.claude/settings.json" > /dev/null
```

Remove `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` from the existing settings `env`, if present, because they conflict with the helper. In OAuth mode, also remove any `GOOGLE_CLAUDE_CLIENT_ID` left over from a previous gcloud setup. Clear static credentials from the shell, close any running Claude Code session, and start again:

```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
unset GOOGLE_CLAUDE_CLIENT_ID
claude --model 'YOUR-GATEWAY-MODEL'
```

Replace `YOUR-GATEWAY-MODEL` with the **existing Model's client-facing name** supplied by the administrator; it may differ from the upstream Provider's model ID. If your organization's model settings already select it, start with plain `claude`. `ANTHROPIC_BASE_URL` alone does not select a model. See [Claude Code model configuration](https://code.claude.com/docs/en/model-config).

Send a short prompt and check `/status` for the gateway URL, credential source, and model. With the example base URL, Messages requests go to `https://gateway.example.com/v1/claude/v1/messages`. The helper's `token` command stays noninteractive. If it requests a new login, run `login` from a terminal with the same configuration and restart Claude Code. See [Claude Code's gateway configuration](https://code.claude.com/docs/en/llm-gateway-connect).

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
