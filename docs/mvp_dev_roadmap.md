# AgentGate MVP開発ロードマップ

> AIエージェント専用 JIT認可プロキシ
> 作成日: 2026-03-24 / 更新日: 2026-03-27

---

## 全体スケジュール

```
Phase 1: プロキシ基盤
  Step 1: プロジェクト基盤         ✅ 完了
  Step 2: ポリシーエンジン         ✅ 完了
  Step 3: リバースプロキシ         ✅ 完了
  Step 4: 監査ログ                ✅ 完了
  Step 5: エージェント認証         ✅ 完了

Phase 2: マルチプロバイダ + インテント解析
  Step 6: マルチプロバイダ対応      ✅ 完了
  (Google Calendar / Microsoft Graph / Slack)

Phase 3: バックエンド堅牢化
  Step 7: レート制限 + クォータ     ✅ 完了
  Step 8: リクエストバリデーション   ✅ 完了
  Step 9: ポリシーエンジン v2       ✅ 完了
  Step 10: エージェントストア強化    ✅ 完了

Phase 4: 運用品質
  Step 11: 監査ログ強化             ✅ 完了
  Step 12: Webhook / アラート       ✅ 完了
  Step 13: Docker化 + CI           ✅ 完了

Phase 5: 統合 + 公開準備
  Step 14: E2Eテスト               ✅ 完了
  Step 15: MCP Auth Proxy          ✅ 完了

Phase 6: OSS公開 + SDK
  Step 16: MIT License + README強化  ✅ 完了
  Step 17: Python SDK               ✅ 完了
  Step 18: TypeScript SDK            ✅ 完了
  Step 19: CI SDK テスト追加         ✅ 完了
```

---

## Phase 1: プロキシ基盤 ✅

### Step 1: プロジェクト基盤 ✅

- FastAPIプロジェクト構造
- Pydantic BaseSettings による設定管理
- loguru による3層ロギング（コンソール / ファイル / エラー専用）
- OWASPセキュリティヘッダーミドルウェア
- CORS設定 + ヘルスチェックエンドポイント

### Step 2: ポリシーエンジン ✅

- YAML形式のポリシーファイル読み込み
- HTTPメソッド + URLパス（ワイルドカード対応）による認可判定
- 時間帯制限（曜日 + 時間帯、タイムゾーン対応）
- first-match-wins ルール評価、デフォルト deny

### Step 3: リバースプロキシ ✅

httpxベースの透過プロキシ。

```
1. エージェントが /proxy/{provider}/{path} にリクエスト
2. X-Agent-Key ヘッダーでエージェント認証
3. プロバイダ紐付け検証
4. レート制限チェック
5. インテント解析（L1/L2）
6. ポリシー評価
7. 許可 → upstream APIに転送 / 拒否 → 403 + 構造化レスポンス
8. 全リクエストを監査ログに記録
```

### Step 4: 監査ログ ✅

SQLite非同期ストレージ。provider / intent / intent_confidence カラム対応。

### Step 5: エージェント認証 ✅

APIキーベース + JSONファイルバックのレジストリ。

---

## Phase 2: マルチプロバイダ + インテント解析 ✅

### Step 6: マルチプロバイダ対応 ✅

- コネクタアーキテクチャ: Google Calendar / Microsoft Graph / Slack
- L1(HTTPメソッド) / L2(パスパターン) の2段階インテント解析
- Slack POST-as-read ハンドリング
- プロバイダ別ポリシー（5ファイル）
- 構造化拒否レスポンス（intent情報 + 代替手段サジェスション）

---

## Phase 3: バックエンド堅牢化

### Step 7: レート制限 + クォータ ✅

- エージェント単位のsliding windowレート制限（分/時）
- ポリシーYAMLに `rate_limit` セクション追加
- 429レスポンス + `Retry-After` ヘッダー
- 監査ログに `rate_limited` decision記録
- テスト: 7ケース

**ファイル:** `backend/app/rate_limiter.py`

### Step 8: リクエストバリデーション ✅

- パスサニタイズ（path traversal / null byte 防止）
- ヘッダーインジェクション検知
- リクエストボディサイズ制限（1MB）
- プロバイダ−エージェント紐付け検証（provider_mismatch 403）
- テスト: 7ケース

**ファイル:** `backend/app/middleware/validation.py`

### Step 9: ポリシーエンジン v2 ✅

- インテントベースのルール評価（`intent` フィールドでマッチ）
- ポリシーの動的リロード（`reload_if_changed()` — mtime検知）
- YAMLスキーマバリデーション（必須フィールド、effect値、ルール構造）
- 複合条件（`conditions` with `and`/`or` ロジック）
- テスト: 19ケース

**ファイル:** `backend/app/policy.py` (v2), `backend/tests/test_policy_v2.py`

### Step 10: エージェントストア強化 ✅

- JSON → SQLite移行（`agents.db`）+ 既存JSONからの自動マイグレーション
- APIキーローテーション（`POST /agents/{id}/rotate-key`）
- エージェント単位の利用統計（`GET /agents/{id}/stats`）
- O(1) APIキールックアップ（インメモリキャッシュ）
- `request_count`, `deny_count`, `deny_rate`, `last_request_at` 追跡

**ファイル:** `backend/app/agents.py` (SQLite版)

---

## Phase 4: 運用品質

### Step 11: 監査ログ強化 ✅

- エクスポート（`GET /audit/export?format=json|csv`）
- 自動パージ（`POST /audit/purge?retention_days=90`）
- 集計エンドポイント（`GET /audit/stats` — by_decision, by_provider, deny_rate, avg/max latency）

### Step 12: Webhook / アラート ✅

- deny/rate_limited発生時のWebhook通知（`POST /webhooks`）
- 閾値ベースアラート（`POST /alerts/thresholds` — count/window/agent_id）
- クールダウン機能（同一アラートの重複発火防止）
- イベントログの自動プルーニング
- テスト: 6ケース

**ファイル:** `backend/app/webhook.py`, `backend/tests/test_webhook.py`

### Step 13: Docker化 + CI ✅

- Dockerfile（python:3.12-slim、非rootユーザー）
- docker-compose.yaml（ボリュームマウント、ヘルスチェック）
- GitHub Actions CI（ruff lint/format + pytest + Docker build検証）

**ファイル:**
- `backend/Dockerfile`
- `docker-compose.yaml`
- `.github/workflows/ci.yaml`

---

## Phase 5: 統合 + 公開準備

### Step 14: E2Eテスト ✅

- モックupstreamを使った全フロー統合テスト（20ケース）
- allow/deny/rate_limit/provider_mismatch/auth 一連フロー検証
- 監査ログ統合検証（allow/deny → audit entry確認）
- エージェントライフサイクル（create → list → stats → rotate-key → delete）
- Webhook/アラート登録フロー
- Health/Discovery/Policies エンドポイント

**ファイル:** `backend/tests/test_e2e.py`

### Step 15: MCP Auth Proxy ✅

- **MCP JSON-RPC プロキシ** — `tools/call` をインターセプトしてポリシー評価
- **アノテーション → ポリシー自動変換** — `readOnlyHint`, `destructiveHint`, `idempotentHint` → intent分類 → ルール自動生成
- **APIエンドポイント:**
  - `POST /mcp/servers` — MCP Server登録 + ツールアノテーション一括登録
  - `POST /mcp/{server_name}` — JSON-RPC リクエスト転送（認可付き）
- 非tools/callメソッド（resources/list等）は透過的に転送
- 監査ログにprovider=mcp, method=MCP:tools/call で記録
- テスト: 14ケース

**ファイル:**
- `backend/app/mcp/proxy.py` — MCPAuthProxy本体
- `backend/app/mcp/annotations.py` — アノテーション → ポリシー変換
- `backend/tests/test_mcp.py`

---

## 技術スタック

| 層 | 技術 |
|---|---|
| Backend | Python 3.12 + FastAPI (async) |
| Proxy | httpx |
| Policy | YAML + fnmatch |
| Rate Limit | In-memory sliding window |
| Audit DB | SQLite (aiosqlite) |
| Agent Store | SQLite (aiosqlite) |
| MCP | JSON-RPC 2.0 proxy |
| Logging | loguru |
| Config | Pydantic BaseSettings |
| Lint | ruff |
| CI | GitHub Actions |
| Container | Docker + docker-compose |

---

## テスト状況

187テスト全通過（2026-03-27時点）

### バックエンド（111テスト）

| テストファイル | ケース数 | 対象 |
|---|:---:|---|
| test_connectors.py | 8 | コネクタ基盤 |
| test_e2e.py | 20 | E2E統合テスト |
| test_intent.py | 10 | インテント解析 |
| test_mcp.py | 14 | MCP Auth Proxy |
| test_policy.py | 20 | ポリシーエンジン v1 |
| test_policy_v2.py | 19 | ポリシーv2 (intent/reload/validation/conditions) |
| test_rate_limiter.py | 7 | レート制限 |
| test_validation.py | 7 | バリデーション |
| test_webhook.py | 6 | Webhook / アラート |

### Python SDK（44テスト）

| テストファイル | ケース数 | 対象 |
|---|:---:|---|
| test_client.py | 44 | sync/async クライアント、例外マッピング、コンテキストマネージャ |

### TypeScript SDK（32テスト）

| テストファイル | ケース数 | 対象 |
|---|:---:|---|
| client.test.ts | 32 | 全リソース、エラーマッピング、認証バリデーション |

---

## 動作確認方法

```bash
# ローカル起動
cd backend
python3 -m uvicorn app.main:app --reload --port 8100

# Docker起動
docker compose up --build

# エージェント登録
curl -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-agent", "policy": "default", "provider": "google"}'

# プロキシ経由でGET（許可される）
curl http://localhost:8100/proxy/google/calendars/primary/events \
  -H "X-Agent-Key: <返却されたapi_key>" \
  -H "Authorization: Bearer <Google OAuthトークン>"

# プロキシ経由でDELETE（拒否される）
curl -X DELETE http://localhost:8100/proxy/google/calendars/primary/events/abc123 \
  -H "X-Agent-Key: <返却されたapi_key>"

# 監査ログ確認
curl http://localhost:8100/audit/logs \
  -H "X-Master-Key: ag_dev_change_me_in_production"

# テスト実行
cd backend && python3 -m pytest -v
```
