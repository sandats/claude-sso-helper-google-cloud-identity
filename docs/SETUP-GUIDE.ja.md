# Google Cloud IdentityでClaude CodeをGatewayに接続する

[English](SETUP-GUIDE.md) · [README](../README.md)

Google Workspace / Cloud Identityの組織アカウントでログインし、Google ID tokenをClaude Codeの`apiKeyHelper`からKongへ渡すための手順です。上流モデルのAPI資格情報はGateway側で管理します。Anthropic組織のSSO設定やClaudeサブスクリプションのログインとは別の、**Claude Code → Gateway → モデルAPI** の接続を対象にします。

このプロジェクトはコミュニティによる実装です。Google、Anthropic、Kongが保守する公式インテグレーションではありません。

## 前提

- macOSまたはLinux、Python 3.10以上、同じ端末上のブラウザ。
- 対象のWorkspace / Cloud Identity組織配下にあるGoogle Cloudプロジェクト。
- **Internal**のOAuthアプリと、**Desktop app**型クライアントのJSON。
- `apiKeyHelper`を利用できるClaude Codeと、Anthropic Messages API形式で接続できるHTTPSのGateway。
- Google OIDC認証とユーザー認可を利用できるKong環境。同梱例はAI Gateway v2向けです。通常の[Kong OIDCプラグインはEnterprise機能](https://developer.konghq.com/plugins/openid-connect/)です。このOSSにGateway製品の利用権やモデルAPI利用権は含まれません。

**この手順を始める前に、対象環境のCP・Model・Providerが作成・設定済みであることが必須です。** Gateway管理者は次の状態を確認してください。

| 既存リソース | 必要な状態 |
| --- | --- |
| CP（Control Plane） | KonnectのAI Gateway v2のCPが存在し、管理者が対象組織・リージョンの設定を参照・更新できる |
| Provider（AI Model Provider） | CP配下に上流LLMへの接続先と有効な認証情報が設定され、対象モデルの利用権がある |
| Model（AI Model） | CP配下に利用するモデルが存在し、上記Providerへ紐付いている。Claude Codeから指定するモデル名が決まっている |
| DP（Data Plane）と接続先URL | CPへ接続したDPが稼働し、利用者の端末からHTTPSで到達できる。既存の認証方式でAnthropic Messages API形式のモデル呼び出しを確認済み |

本ガイドでは、この既存環境へGoogle SSOを追加します。CP・Model・Provider・DPの新規構築は含みません。未構築の場合は先に[Kong AI Gatewayのセットアップ](https://developer.konghq.com/ai-gateway/)を完了してください。管理者は第3章で使用する既存のkongctl YAMLを用意し、利用者へ第4章で設定する**GatewayのベースURLと利用可能なモデル名**を案内します。ベースURLはモデルへのリクエスト先であり、Konnectの管理API URLではありません。

Windowsネイティブ、SSH先、Cloud Shell、別端末のブラウザを使うログインには対応していません。以下はリポジトリのルートで実行し、`example.com`、アカウント、パス、Gateway URLを置き換えます。

## 1. GoogleのDesktop OAuthクライアントを作る

[Google Cloudコンソール](https://console.cloud.google.com/)で対象組織配下のプロジェクトを選び、**Google Auth Platform**で次を設定します。

1. **Branding**にアプリ名と連絡先を設定します。
2. **Audience**を**Internal**にします。対象組織のユーザー向けのアプリです。
3. **Clients**から**Desktop app**型のクライアントを作ります。
4. 作成時にJSONをダウンロードし、安全な場所へ保存します。

JSONには`installed`オブジェクトと、その中に`client_id`、`client_secret`が必要です。Web application型やサービスアカウントキーは入力できません。JSONのキー名を変えても登録したクライアントの種類は変わりません。

Helperは`openid email`を要求し、Authorization Code + PKCEと、`127.0.0.1`の一時的なポートへのコールバックを使います。Desktopクライアントのsecretは配布先で秘匿できる前提ではないため、それ自体をユーザー認可の根拠にはできません。[GoogleのDesktop OAuth仕様](https://developers.google.com/identity/protocols/oauth2/native-app)、[Internal Audience](https://support.google.com/cloud/answer/15549945?hl=en)

組織のポリシーでブロックされる場合、管理者に**client ID**を渡して[アプリのアクセス制御](https://support.google.com/a/answer/7281227?hl=ja)を確認してもらいます。端末へDirectory API管理権限やサービスアカウントキーを配布する必要はありません。

## 2. インストールして初回ログインする

クライアントJSONはリポジトリの外に置きます。(`client_secret_desktop.json`は通常MDMなどで一斉配布することを想定しています)

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

ブラウザで組織アカウントを選び、認証と同意を完了します。待機時間は3分です。ブラウザが開かなければ、表示されたURLを同じ端末のブラウザで開きます。`login --no-browser`も同じ端末へのコールバックが必要です。

ここでは第3章で管理者が検証済みのユーザーを登録できるよう、明示的に初回ログインしています。既にユーザーが登録されている場合は、第4章の`token --auto-login`設定を使い、Claude Codeが最初に資格情報を要求するときにブラウザ認証を開始することもできます。

`status`は署名検証済みの`iss / aud / sub / email / hd / exp`を表示し、トークン自体は表示しません。`aud`がJSONの`installed.client_id`、`hd`が許可する組織ドメインと一致することを確認します。出力には個人を識別する情報が含まれるため、公開Issueには貼り付けないでください。

## 3. Kongの認証と認可を設定する

この章は**Gateway管理者**が実施します。[前提](#前提)のCP・Model・Providerと稼働中のDPを用意したうえで、[kongctl](https://developer.konghq.com/kongctl/)をインストールし、対象のKonnect組織・リージョンへ接続できる状態にします。そのGatewayを管理している既存のkongctl YAMLファイルが必要です。[kongctl-oidc.example.yaml](../examples/kongctl-oidc.example.yaml)は、そのファイルへ組み込む**部分設定例**です。モデルやプロバイダを作る設定は含みません。

### 3.1. 設定するものを確認する

Kongでは「誰からのリクエストか」の認証と、「そのユーザーがモデルを使えるか」の認可を次の設定で行います。

| 設定 | 役割 | 同梱例の名前 |
| --- | --- | --- |
| Auth strategy（認証方式） | Google ID tokenの署名・期限と、今回のアプリ向けのトークンかを検証する | `google-desktop-oidc` |
| Consumer（利用者） | Googleのユーザー識別子`sub`を`custom_id`へ登録し、利用を許可するユーザーを識別する | `google-user-example` |
| Consumer Group（利用者グループ） | Consumerをまとめ、モデルへのアクセス許可に使う | `claude-standard-users` |
| モデルの`access` | 使用する認証方式と、アクセスを許可するグループを指定する | 保護する既存モデルごとに設定 |

この例は、Google ID tokenの`sub`から登録済みConsumerを探し、そのConsumerが許可グループに所属しているかを確認する構成です。認証方式を作るだけではモデルは保護されないため、3.3でモデルにも紐付けます。

### 3.2. 環境変数に値を設定する

`kongctl`を実行するターミナルで、次の値を設定します。以下の値は例なので、自分の環境の値へ置き換えてください。

| 環境変数 | 設定する値・取得元 |
| --- | --- |
| `CLIENT_ID` | 第1章でダウンロードしたDesktop OAuthクライアントJSONの`installed.client_id`。第2章の`status`の`aud`と同じ値 |
| `GOOGLE_USER_SUB` | 利用を承認したユーザーのGoogle `sub`。第2章の`status`で確認できるが、登録前に管理者による本人・組織所属の確認が必要 |
| `OIDC_CACHE_TOKENS_SALT` | KongのOIDCキャッシュ用の固定値。認証方式の新規作成時に一度生成し、再適用時も同じ値を使う |
| `KONG_CONFIG` | 対象Gatewayを管理している既存のkongctl YAMLファイルのパス。3.3でこのファイルを編集する |

```bash
export CLIENT_ID='123456789012-example.apps.googleusercontent.com'
export GOOGLE_USER_SUB='123456789012345678901'
export KONG_CONFIG='/absolute/path/to/your-existing-kongctl.yaml'

# 新規作成時のみ生成する。管理者の保管先に保存し、次回は同じ値を設定する
export OIDC_CACHE_TOKENS_SALT="$(openssl rand -hex 32)"
```

`cache_tokens_salt`はAI Gateway v2のOIDC認証方式で必要なキャッシュキー生成用の値です。Googleのclient secretとは別の値で、`!env OIDC_CACHE_TOKENS_SALT`から設定します。既存の認証方式を更新する場合は、新しく生成せず保管済みの値を使ってください。[Kong AI Auth Strategies](https://developer.konghq.com/ai-gateway/entities/ai-auth-strategy/)

同梱YAMLは次のように`!env`で参照します。**YAML内のクライアントIDや`custom_id`を書き換える必要はありません。** `client_id`は使用するOAuthクライアント、`audience_required`は受け入れるID tokenの`aud`を指定し、この構成では両方に同じ`CLIENT_ID`を使います。

```yaml
client_id:
  - !env CLIENT_ID
audience_required:
  - !env CLIENT_ID
```

Consumerの`custom_id`も`!env GOOGLE_USER_SUB`から読み込みます。これらはkongctlが読み込む変数なので、Claude Codeの`settings.json`に追加する必要はありません。別のターミナルやCIで実行する場合も、その実行環境に設定してください。`!env`は未設定ならエラーになりますが、空文字は許されるため、3.4のコマンドで空の値も確認します。[kongctlの環境変数参照](https://developer.konghq.com/kongctl/declarative/#loading-values-from-environment-variables)

管理者はユーザーのGoogle署名と組織所属を独立して検証したうえでConsumerを登録します。ユーザーが送った`status`出力のコピーだけを本人確認の証拠にはできません。

### 3.3. 既存のGateway設定へ組み込む

`KONG_CONFIG`で指定したファイルをエディタで開き、次を行います。`ref`はYAML内のリソースを識別する名前で、`!ref`はそのリソースへの参照です。Konnectが発行するUUIDとは異なります。

1. 既存の`ai_gateways`から対象Gatewayの`ref`を確認し、同梱例にあるすべての`YOUR-EXISTING-GATEWAY-REF`をその値に合わせます。
2. 同梱例の`auth_strategies`、`consumers`、`consumer_groups`の各項目を、そのGatewayの下に追加します。同じキーが既にある場合はリストへ項目を追加し、同じ`ref`の項目があればその項目を更新します。`ai_gateways:`や同じGatewayを重複して貼り付けないでください。既存のモデル・プロバイダ・上流資格情報・ポリシーは保持します。
3. 対象Gatewayの`models`にある**保護するすべてのモデル**へ、次の`access`を組み込みます。既存の`access`がある場合は、その認証方式・許可グループを確認し、意図するアクセス権になるよう編集します。

```yaml
# 既存モデルの ref や name と同じインデントで追加する
access:
  auth_strategies:
    - !ref google-desktop-oidc
  acls:
    allow:
      - claude-standard-users
```

`acls.allow`は、アクセスを許可するConsumer Groupの名前の一覧です。同梱例では`google-user-example`を`claude-standard-users`へ登録しています。利用者を増やすときは、ユーザーごとに別の`ref`・`name`・`sub`用環境変数を持つConsumerを追加し、グループの`consumers`にも参照を追加します。同じConsumerの`GOOGLE_USER_SUB`を別人の値に変更すると、既存ユーザーの登録を置き換えることになります。

### 3.4. 差分を確認して適用する

3.2で環境変数を設定したターミナルで実行します。`kongctl login`が未実施なら、先に対象環境の設定でログインします。普段`--profile`や`--region`を指定している場合は、差分確認と適用でも同じ指定を使ってください。

```bash
kongctl login

# 未設定・空文字の場合は、ここで止めて値を確認する
: "${CLIENT_ID:?Set CLIENT_ID to the Desktop OAuth client ID}"
: "${GOOGLE_USER_SUB:?Set GOOGLE_USER_SUB to the approved Google user sub}"
: "${OIDC_CACHE_TOKENS_SALT:?Set OIDC_CACHE_TOKENS_SALT to the saved salt}"
: "${KONG_CONFIG:?Set KONG_CONFIG to the merged gateway YAML path}"

kongctl diff --mode apply -f "$KONG_CONFIG"
```

差分に今回の認証方式、Consumer、グループ所属、各モデルの`access`が含まれ、対象Gatewayと既存設定への変更が意図どおりであることを確認します。続けて、同じ環境変数のまま適用します。

```bash
kongctl apply -f "$KONG_CONFIG"
```

`apply`が表示する変更を確認し、確認プロンプトに`yes`と入力します。適用対象は**3.3で編集した既存設定ファイル**です。同梱の部分設定例をそのまま単体で適用する手順ではありません。`apply`は作成・更新を行い、`sync`は削除も扱うため、この手順では`apply`を使います。[kongctlの差分確認と適用](https://developer.konghq.com/kongctl/declarative/#create-your-first-configuration)

### 3.5. 認証・認可の動作を確認する

- `auth_methods: [bearer]`でBearerトークンを受け付け、`consumer_claims: [[sub]]`、`consumer_by: [custom_id]`でユーザーを識別します。`consumer_optional: false`により、登録したConsumerに一致しないユーザーは拒否します。
- `Authorization`と`x-api-key`の両方をログで秘匿し、上流へ転送する前に除去します。`hide_credentials`や追加のヘッダー制御で両方を処理できているか確認します。
- 既存のemailマッピングから移行する場合、Consumer識別子とclaim設定を合わせて変更します。同じAI Gateway内でOIDCを使うモデルは同じauth strategyを参照する必要があるため、既存のOIDC認証方式がある場合は、その更新とモデルの参照変更をまとめて計画します。[Kong AI Auth Strategies](https://developer.konghq.com/ai-gateway/entities/ai-auth-strategy/)

**ローカルHelperのチェックはGatewayの認可を代行しません。** 利用者はHelperを使わず直接HTTPを送れます。同梱例はInternalアプリ、audience、承認済み`sub`の許可リストを使いますが、Gatewayで毎リクエスト`hd`を検査する設定は含みません。必要なら信頼できるサーバー側の検査を追加してください。ログイン画面の`hd`ヒントだけではアクセス制限になりません。[GoogleのID token検証仕様](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken)

AI Gateway v2と通常のOIDCプラグインでは設定項目が異なります。導入環境の項目は次のコマンドで確認できます。疎通と拒否条件の検証は第5章へ進んでください。

```bash
kongctl explain ai_gateways.auth_strategies.config --extended
kongctl explain ai_gateways.consumers --extended
kongctl explain ai_gateways.consumer_groups --extended
```

### Google Groups

同梱例の`claude-standard-users`は**Kong側で管理するグループ**です。Google Groupsと同じ名前にしても所属は連携されません。まずはGoogle Groupsを設定せず、3.3でConsumerをこのグループへ登録することで、承認したユーザーのアクセスを設定できます。

Google Groups連携を自動化する場合は、Directory APIまたはCloud Identity APIから管理側で取得し、Kongへ同期する処理が別途必要です。削除・退職時の反映、ページネーション、ネストした所属、API障害時の扱いも設計します。自動同期は本プロジェクトに含まれません。Googleの署名済みJWTに`groups`を追加したり、ユーザーが送るグループヘッダーを認可根拠にしたりしないでください。

## 4. Claude Codeを設定する

この章は**Claude Codeを使う利用者の端末**で実施します。[claude-settings.example.json](../examples/claude-settings.example.json)を元に、利用者設定の`~/.claude/settings.json`を編集します。サンプルファイルをリポジトリ内で変更しただけではClaude Codeへ反映されません。組織が設定を一括管理している場合は、管理者が同じ項目を組織管理設定へ反映します。[Claude Codeの設定ファイル](https://code.claude.com/docs/en/settings)

### 4.1. 設定ファイルを用意する

第2章でログインした端末のリポジトリルートで実行します。既存の設定ファイルがある場合は日時付きでバックアップし、ない場合だけサンプルをコピーします。

```bash
mkdir -p "$HOME/.claude"
if [ -f "$HOME/.claude/settings.json" ]; then
  cp -p "$HOME/.claude/settings.json" \
    "$HOME/.claude/settings.json.backup-$(date +%Y%m%d-%H%M%S)"
else
  cp examples/claude-settings.example.json "$HOME/.claude/settings.json"
fi
```

続けて`~/.claude/settings.json`をエディタで開きます。既存ファイルの場合は、サンプルの`apiKeyHelper`を追加・更新し、サンプルの`env`内の各項目を既存の`env`へ追加・更新してください。`env`全体を置き換えず、既存のモデル設定、`permissions`、`hooks`や今回と無関係な環境変数は残します。同じキーを二重に書かないでください。

### 4.2. サンプルの値を書き換える

JSONの`env`内の値はすべて文字列として記載します。次の表のパス・URL・ドメイン・アカウントを自分の環境に合わせてください。

| 編集するキー | 設定する値・取得元 |
| --- | --- |
| `apiKeyHelper` | 第2章でインストールした`.venv/bin/google-claude-auth`の絶対パスと、末尾の`token --auto-login`。パスを囲む`\"`は残す。非対話で使う場合は`token`のみを指定する |
| `env.ANTHROPIC_BASE_URL` | Gateway管理者から案内されたHTTPSのベースURL。例：`https://gateway.example.com/v1/claude`。末尾に`/v1/messages`を付けない |
| `env.GOOGLE_CLAUDE_CLIENT_FILE` | 第2章で使ったDesktopクライアントJSONの絶対パス。例：`/Users/example/.config/claude-google-sso/client_secret_desktop.json` |
| `env.GOOGLE_CLAUDE_DOMAINS` | 第2章の`GOOGLE_CLAUDE_DOMAINS`と同じ組織ドメイン。例：`example.com` |
| `env.GOOGLE_CLAUDE_ACCOUNT` | 第2章でログインしたアカウント。例：`user@example.com`。第2章でアカウントを固定しなかった場合は、このキーを削除する |
| `env.GOOGLE_CLAUDE_AUTH_MODE` | 通常の導入では`"oauth"`のまま |
| `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS` | 第2章と同じ値。通常は`"300000"`のまま（5分） |

HelperとクライアントJSONのパスは、第2章の環境変数が設定されたターミナルで次のように確認できます。

```bash
printf '%s/.venv/bin/google-claude-auth\n' "$(pwd -P)"
printf '%s\n' "$GOOGLE_CLAUDE_CLIENT_FILE"
```

JSON内では`$HOME`や`~`がシェルと同様に展開される前提にせず、実際の絶対パスを記載してください。`GOOGLE_CLAUDE_CLIENT_FILE`にはOAuthクライアントJSONを指定し、トークンのキャッシュファイルを指定しないでください。任意の`GOOGLE_CLAUDE_CACHE_DIR`を第2章で設定した場合は、同じ絶対パスを`env`にも追加します。mode・client・account・domains・cache directoryを初回ログインと揃えることで、同じトークンキャッシュを利用できます。

たとえば、macOSでリポジトリが`/Users/example/projects/claude-sso-helper-google-cloud-identity`にある場合、今回の設定項目は次のようになります。これはパス等を書き換えた例なので、そのまま貼り付けず、自分の値に合わせてください。既存の設定項目はこの例に追加して保持します。

```json
{
  "apiKeyHelper": "\"/Users/example/projects/claude-sso-helper-google-cloud-identity/.venv/bin/google-claude-auth\" token --auto-login",
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

第3章の`CLIENT_ID`、`GOOGLE_USER_SUB`、`OIDC_CACHE_TOKENS_SALT`はkongctl用なので、このJSONには追加しません。ProviderのAPIキーやGoogle ID tokenをJSONへ貼り付ける必要もありません。資格情報は`apiKeyHelper`が取得します。

### 4.3. JSONを確認して起動する

保存後にJSONの構文を確認します。正常なら何も表示されず終了します。エラーの場合は示された位置を修正してください。JSONにはコメントや末尾の余分なカンマを書けません。

```bash
.venv/bin/python -m json.tool "$HOME/.claude/settings.json" > /dev/null
```

既存の`settings.json`の`env`に`ANTHROPIC_API_KEY`や`ANTHROPIC_AUTH_TOKEN`があれば、Helperと競合するため削除します。OAuthモードでは、過去のgcloud設定などの`GOOGLE_CLAUDE_CLIENT_ID`が残っていれば削除してください。shell側の静的資格情報も解除して、起動済みのClaude Codeを終了してから起動します。

```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
unset GOOGLE_CLAUDE_CLIENT_ID
claude --model 'YOUR-GATEWAY-MODEL'
```

`YOUR-GATEWAY-MODEL`は、管理者から案内された**既存Modelのクライアント向けモデル名**に置き換えます。上流ProviderのモデルIDと同じとは限りません。既に組織のモデル設定で選択される場合は、通常の`claude`で起動できます。`ANTHROPIC_BASE_URL`だけではモデルは選択されません。[Claude Codeのモデル設定](https://code.claude.com/docs/en/model-config)

短いメッセージを送り、`/status`でGateway URL・認証元・モデルを確認します。上記URLの例では、Messages APIのリクエスト先は`https://gateway.example.com/v1/claude/v1/messages`になります。Googleログインのブラウザが開いた場合は、同じ端末でアカウント選択・同意・必要なMFAを完了します。Helperは検証済みID tokenをClaude Codeへ返し、処理を続行します。[Claude Code公式のGateway設定](https://code.claude.com/docs/en/llm-gateway-connect)

#### 自動ログイン

既存環境で有効にする場合は、リポジトリのルートで`.venv/bin/python -m pip install .`を実行して更新し、既存の`apiKeyHelper`の`token`の後ろへ`--auto-login`を追加してClaude Codeを再起動します。明示的なPythonインタープリター指定や、引用符で囲んだ絶対パスは保持してください。プロジェクト専用の設定を使う場合は、そのプロジェクトで`claude --settings ./.claude/settings.json`と起動します。

`token --auto-login`は有効なキャッシュの利用とブラウザ不要のrefreshを優先します。キャッシュがない・不完全な場合、またはrefreshが`invalid_grant`を返した場合に、1回だけブラウザ認証を開始します。通信障害、OAuthクライアントの設定ミス、署名・ユーザー情報の検証エラー、キャッシュの破損・権限エラーでは認証画面を開かず、エラーを返します。認証失敗・キャンセル時は既存キャッシュを保持し、資格情報を出力しません。再認証では保存済みのGoogle `sub`と同じユーザーである必要があり、意図的にアカウントを変える場合は明示的に`login`を実行します。自動ログインでGatewayのユーザー登録や認可設定が変わることはありません。

ブラウザからのコールバックの待機上限は180秒で、その後にトークン交換・検証を行います。自動ログインが同時に呼ばれた場合、後続の呼び出しは最大300秒キャッシュのロックを待ち、完了済みのログインを再利用します。ローカルで確認したClaude Code 2.1.266の実装では、`apiKeyHelper`の実行上限は600秒です。別バージョンを使う場合は互換性を確認してください。Claude Codeが10秒後に表示することのあるHelper遅延の通知は、実行タイムアウトではありません。`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`は資格情報のキャッシュ時間であり、認証の待機時間ではありません。[Claude Codeの資格情報管理](https://code.claude.com/docs/en/authentication#credential-management)

無人実行や手動ログインを前提とする場合は、`--auto-login`を付けません。`token`のみなら従来どおり非対話で動き、認証が必要なときは同じ環境変数で`login`を実行してClaude Codeを再起動します。`--auto-login`はOAuthモードの`token`専用で、`status`・`login`・`logout`やgcloudモードには使えません。`token --auto-login --no-browser`はURLをstderrへ表示し、同じ端末のブラウザで手動で開く場合に使えます。

## 5. 検証する

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -v
```

オフラインテストではテスト用のRSA鍵を生成し、実際の署名検証を行います。Googleの応答はテスト用に置き換え、実アカウントやモデルAPIを使用しません。PKCEのテストには端末内のloopback通信が必要です。

GoogleログインとGateway設定が完了したら、任意で疎通確認を実行できます。**正常ケースは最大8出力トークンのモデルAPI利用を伴います。**

```bash
.venv/bin/google-claude-verify-gateway \
  --base-url 'https://gateway.example.com/v1/claude' \
  --model 'YOUR-GATEWAY-MODEL'
```

トークン無し・署名改ざんは401または403、正常Google ID tokenは200のMessages応答が期待値です。出力はケース名、HTTPステータス、合否のみで、資格情報やモデル応答本文は表示しません。

専用Desktopクライアントでの実ログインと更新、Claude Code本体の起動、Gateway側の別audience・期限切れ・未登録ユーザー・組織ポリシー外ユーザーの拒否、モデルACL、所属変更、利用停止、資格情報の除去は導入先で確認します。3ケースの成功だけでこれらを検証したことにはなりません。Helperが拒否するだけではGateway側の拒否を証明できません。

## 保存・更新・ログアウト

| 項目 | 動作 |
| --- | --- |
| 保存先 | `~/.claude/google-sso/<設定別ハッシュ>/tokens.json` |
| 保存内容 | ID tokenとrefresh tokenを**平文**で保存。OS Keychain連携なし |
| 権限 | ディレクトリ0700、ファイル0600、排他ロックと原子的置換 |
| Helper TTL | 既定300000ミリ秒。設定できる範囲は0〜300000 |
| 更新条件 | 残り有効期間がTTL＋60秒以下の場合に更新 |
| 鍵の取得 | 検証ごとにGoogleからHTTPS取得。取得できなければ資格情報を返さず終了 |

```bash
.venv/bin/google-claude-auth logout
```

削除するのは現在の設定のローカルキャッシュだけです。Googleへの同意や発行済みID token、Claude Codeのキャッシュは失効しません。利用停止時はClaude Codeを終了し、Gatewayの許可削除と必要なGoogleアプリ利用取消しを行い、反映時間を確認します。[Security](../SECURITY.md)

## エラーの切り分け

| 症状 | 確認箇所 |
| --- | --- |
| Internalを選べない／`org_internal` | プロジェクトとユーザーの組織 |
| Desktop JSONエラー | `installed`を持つDesktop app型のJSONか |
| client ID不一致 | OAuthモードで以前の`GOOGLE_CLAUDE_CLIENT_ID`が残っていないか |
| アプリのブロック | 管理者によるclient IDの利用許可 |
| localhostへ戻れない | ブラウザとHelperが同じ端末か、3分の待機中か、loopbackを許可しているか |
| `hd`／account不一致 | 許可ドメイン、選択した組織アカウント |
| `invalid_grant` | 再ログイン、同意・組織ポリシー |
| `status`成功、Gateway拒否 | audience、反映済みauth strategy、Consumer、モデルACL |
| Claude Codeのみ未ログイン | shellとsettingsの環境変数、絶対パス |
| 署名検証エラー／Googleへ接続できない | Google公開鍵エンドポイントへの接続、端末の時刻 |

開発用の`gcloud`互換モードと環境変数一覧は[英語ガイド](SETUP-GUIDE.md#optional-gcloud-development-compatibility)と[README](../README.md#configuration)を参照してください。通常の導入は専用Desktop OAuthモードを使います。

修正提案は[CONTRIBUTING.md](../CONTRIBUTING.md)、ライセンスは[MIT](../LICENSE)を参照してください。
