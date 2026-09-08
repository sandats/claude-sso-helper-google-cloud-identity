# Google Cloud IdentityでClaude CodeをGatewayに接続する

[English](SETUP-GUIDE.md) · [README](../README.md)

Google Workspace / Cloud Identityの組織アカウントでログインし、Google ID tokenをClaude Codeの`apiKeyHelper`からKongへ渡すための手順です。上流モデルのAPI資格情報はGateway側で管理します。Anthropic組織のSSO設定やClaudeサブスクリプションのログインとは別の、**Claude Code → Gateway → モデルAPI** の接続を対象にします。

このプロジェクトはコミュニティによる実装です。Google、Anthropic、Kongが保守する公式インテグレーションではありません。

## 前提

- macOSまたはLinux、Python 3.10以上、同じ端末上のブラウザ。
- 対象のWorkspace / Cloud Identity組織配下にあるGoogle Cloudプロジェクト。
- **Internal**のOAuthアプリと、**Desktop app**型クライアントのJSON。
- `apiKeyHelper`を利用できるClaude Codeと、Anthropic Messages API形式で接続できるHTTPSのGateway。上流のモデルと資格情報はあらかじめ設定します。
- Google OIDC認証とユーザー認可を利用できるKong環境。同梱例はAI Gateway v2向けです。通常の[Kong OIDCプラグインはEnterprise機能](https://developer.konghq.com/plugins/openid-connect/)です。このOSSにGateway製品の利用権やモデルAPI利用権は含まれません。

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

`status`は署名検証済みの`iss / aud / sub / email / hd / exp`を表示し、トークン自体は表示しません。`aud`がJSONの`installed.client_id`、`hd`が許可する組織ドメインと一致することを確認します。出力には個人を識別する情報が含まれるため、公開Issueには貼り付けないでください。

## 3. Kongの認証と認可を設定する

[kongctl-oidc.example.yaml](../examples/kongctl-oidc.example.yaml)は、既存の**AI Gateway v2宣言へマージする部分設定例**です。モデルやプロバイダは含みません。単体でsyncに渡さず、既存の反映手順に沿って差分を確認します。

- `issuer`をGoogleにし、署名と期限を検証します。`client_id`と`audience_required`に今回のDesktopクライアントIDを設定します。
- `auth_methods: [bearer]`、`consumer_optional: false`で未登録ユーザーを拒否します。
- `consumer_claims: [[sub]]`、`consumer_by: [custom_id]`を使い、承認したユーザーのGoogle `sub`をConsumerの`custom_id`へ登録します。
- 保護する**すべてのモデル**にauth strategyとグループACLを設定します。上流資格情報、既存モデル、レート制限の設定を保持します。
- `Authorization`と`x-api-key`の両方をログで秘匿し、上流へ転送する前に除去します。`hide_credentials`や追加のヘッダー制御で両方を処理できているか確認します。

管理者はユーザーのGoogle署名と組織所属を独立して検証したうえでConsumerを登録します。ユーザーが送った`status`出力のコピーだけを本人確認の証拠にはできません。既存のemailマッピングから移行する場合、Consumer識別子とclaim設定を合わせて変更するか、移行用に別のauth strategyを用意します。

**ローカルHelperのチェックはGatewayの認可を代行しません。** 利用者はHelperを使わず直接HTTPを送れます。同梱例はInternalアプリ、audience、承認済み`sub`の許可リストを使いますが、Gatewayで毎リクエスト`hd`を検査する設定は含みません。必要なら信頼できるサーバー側の検査を追加してください。ログイン画面の`hd`ヒントだけではアクセス制限になりません。[GoogleのID token検証仕様](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken)

AI Gateway v2と通常のOIDCプラグインでは設定項目が異なります。導入環境で確認します。

```bash
kongctl explain ai_gateways.auth_strategies.config --extended
kongctl explain ai_gateways.consumers --extended
kongctl explain ai_gateways.consumer_groups --extended
```

### Google Groups

同梱例のConsumer Group所属は静的設定です。Google Groups連携を自動化する場合は、Directory APIまたはCloud Identity APIから管理側で取得し、Kongへ同期する処理が別途必要です。削除・退職時の反映、ページネーション、ネストした所属、API障害時の扱いも設計します。自動同期は本プロジェクトに含まれません。Googleの署名済みJWTに`groups`を追加したり、ユーザーが送るグループヘッダーを認可根拠にしたりしないでください。

## 4. Claude Codeを設定する

[claude-settings.example.json](../examples/claude-settings.example.json)を利用者の`~/.claude/settings.json`や組織管理設定へマージし、既存のモデル設定等を保持します。

- `apiKeyHelper`を、インストール済みの`.venv/bin/google-claude-auth`コマンドの**絶対パス**へ置き換えます。空白を含むパスのために引用符を保持します。
- `GOOGLE_CLAUDE_CLIENT_FILE`を初回ログインで使ったJSONの絶対パスへ置き換えます。JSON内の`$HOME`がシェルと同様に展開される前提にしないでください。
- mode、account、domains、TTL、任意のcache directoryをログイン時と揃えます。設定が違うと別キャッシュになります。
- `ANTHROPIC_BASE_URL`に`/v1/messages`を含まないGatewayのルート接頭辞を指定します。例の`https://gateway.example.com/v1/claude`なら、リクエスト先は`https://gateway.example.com/v1/claude/v1/messages`です。
- モデル名にはGatewayで提供している名前を指定します。GatewayのAnthropic API形式で接続します。

shellとsettingsの競合する静的資格情報を取り除き、Claude Codeを起動します。

```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
claude
```

短いメッセージを送り、`/status`でGateway URLと認証元を確認します。`token`は非対話で動き、再認証が必要ならエラーを返します。同じ環境変数で`login`を再実行し、Claude Codeを再起動してください。[Claude Code公式のGateway設定](https://code.claude.com/docs/en/llm-gateway-connect)

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
