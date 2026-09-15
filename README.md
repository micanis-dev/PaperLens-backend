# PaperLens backend

仕様書の「Fly.io 東京リージョンのGo API / Supabase FreeのPostgreSQL」境界を実装するバックエンドです。

PaperLens の基本方針に合わせて、PDF本体・論文メタデータ・注釈・翻訳本文はサーバーへ保存しません。Go API は PaperLens 管理 LLM、アカウント、プラン、クレジット台帳、翻訳リクエストの状態だけを扱います。

## 開発

プロジェクトルートで direnv または Devbox shell を有効にしてください。

```sh
cd /Users/micanis/Develop/PaperLens
direnv allow
cd backend
cp .env.example .env
go test ./...
go run ./cmd/api
```

API は `http://127.0.0.1:8080` で起動します。開発環境では PaperLens の外部へ本文を送らない Echo Provider を使うため、APIキーなしで翻訳フロー、冪等性、クレジット予約を確認できます。

```sh
curl http://127.0.0.1:8080/v1/healthz
curl http://127.0.0.1:8080/v1/plans
curl http://127.0.0.1:8080/v1/credits
```

認証はメールアドレス＋12文字以上のパスワードを既定とし、Apple・Google・GitHub OAuthも利用できます。SSOはログイン時に自動でアカウントへ追加せず、パスワードで作成したアカウントの設定画面から、同じメールアドレスを確認したうえで明示的に連携・解除します。OAuthのコールバックURLは各プロバイダーで、`{APP_BASE_URL}/v1/auth/{provider}/callback`（`provider`は`apple`、`google`、`github`）として登録してください。

開発環境では、ログイン画面に4人のテストユーザーが表示されます。`DEV_TEST_USERS`で`id:表示名`のカンマ区切りに変更できます。テストユーザーAPI（`/v1/auth/test-users`）は開発環境だけで有効で、本番では無効です。マジックリンクAPIは既存クライアント互換のため残していますが、フロントエンドの既定ログイン方法ではありません。

## 構成

- `cmd/api` — graceful shutdown 付き HTTP エントリポイント
- `internal/api` — `/v1` の HTTP/JSON API、CORS、共通エラー契約
- `internal/contract` — API とフロントエンドで同期する翻訳・プラン型
- `internal/credits` — append-only クレジット台帳と予約・確定・返却
- `internal/translation` — 入力検証、冪等性、Provider呼び出し、使用量確定
- `internal/provider` — LLM Provider アダプター境界
- `internal/auth` — HttpOnly セッション、パスワード認証、OAuth SSOの境界
- `internal/billing` — Stripe Checkout / Portal / 署名検証済みWebhookのユースケース
- `migrations` — PostgreSQL の最小サーバースキーマ
- `supabase/migrations` — Supabase CLIでリモートへ適用する移行履歴
- `OPERATIONS.md` — バックアップ、復元、Webhook障害、段階ロールバックの運用手順
- `api/openapi.yaml` — API 契約のソース

開発環境ではDATABASE_URLを空にしたメモリRepository / Ledgerを利用できます。DATABASE_URLを設定すると起動時にSupabase PostgreSQLへ接続し、初期スキーマを適用して、翻訳リクエストのメタデータ・クレジット台帳・ログアウト失効を永続化します。翻訳本文とPDFはPostgreSQLへ保存しません。本番ではDATABASE_URLが必須です。

## 重要な仕様

- PaperLens 管理 LLM のみクレジットを消費
- 基準は `ceil(inputTokens / 1000) + 2 * ceil(outputTokens / 1000)`。管理LLMはモデル別倍率を適用し、入力1,000＋出力1,000トークンの目安は Astra 30、Sol 12、Terra 6、Luna 3、Shisa 3、TranslateGemma 3、Gemini 3.8 Flash 6クレジットとする（料金表は管理者が変更可能）。
- 管理LLMのモデルは `gpt-6-astra`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-5.6-luna`、`shisa-ai/shisa-v2.1-llama3.3-70b`、`google/translategemma-27b-it`、`gemini-3.8-flash` から選択する。選択値は設定済みのOpenAI互換エンドポイントへそのまま送信される。
- `Idempotency-Key` は 36〜128 文字、同一キーの本文違いは 409
- クレジットは残高の直接更新ではなく `grant / reserve / consume / release / refund / expire` の台帳
- 本番環境で管理LLM未設定の場合はAPIを起動できるが、翻訳だけ安全側に失敗し、勝手に別Providerへ送信しない
- 認証済み API は HttpOnly セッション Cookie を前提にし、Bearer token を localStorage に保存しない
- アカウント削除は直近の完全再認証を要求し、24時間の取消猶予後にサーバー所有データを削除・匿名化する
- 料金換算ポリシーは`ADMIN_USER_IDS`で許可した管理者だけが`/v1/admin/rates`から変更でき、PostgreSQL利用時は再起動後も保持される
- `GET /v1/internal/metrics` は管理者セッション専用のPrometheus互換出力で、5xx/429、翻訳失敗、台帳不整合、Providerレイテンシ、月次原価を記録する
- 再起動後に残った古い翻訳ジョブは定期的に予約を返却して失敗状態へ移し、冪等性キーが永久に待機し続けない

## デプロイ

`fly.toml` は `nrt`、常時起動、`/v1/healthz` チェック、`0.0.0.0:8080` を設定済みです。PostgreSQLはSupabase Free（`ap-northeast-1`）を使い、APIの秘密値はFly Secretsへ登録します。

```sh
supabase db push --linked
fly secrets set DATABASE_URL=... SESSION_SECRET=... ADMIN_USER_IDS=...
# 管理LLMを有効化するときだけ、次の3変数も追加する
# fly secrets set PAPERLENS_LLM_BASE_URL=... PAPERLENS_LLM_API_KEY=... PAPERLENS_LLM_MODEL=...
fly deploy
```

Stripeは全キーとPrice IDを設定した場合だけCheckout / Portalを有効にします。既存契約のアップグレードは即時変更、ダウングレードはStripe Subscription Schedule（Freeは`cancel_at_period_end`）へ登録し、現在の請求期間終了まで権限を維持します。`/v1/stripe/webhook` はStripe署名、イベント時刻、顧客整合性を検証し、原子的な処理予約・重複排除・順序逆転保護を行います。OAuthとメールマジックリンクは設定時に有効になり、PostgreSQL利用時は短期チャレンジをハッシュ化して永続化します。Stripe secret、OAuth client secret、Apple private key、Provider key、PDF本文をリポジトリやログへ置かないでください。
