# Azure OpenAI API key passthrough (`azureOpenAIPassthrough`)

Remote clients (Agent API Key + `REMOTE_AGENTS` permission) can call Azure OpenAI **REST** through QIMAgpt without embedding secrets in the client. All paths are under:

**`/api/agents/v1/azure/`**

Set the OpenAI-compatible base URL to:

`https://<host>/api/agents/v1/azure`

Use **`Authorization: Bearer <LibreChat Agent API Key>`** (same as other `/api/agents/v1/*` routes).

## What this module implements (passthrough)

| Method | Local path | Upstream (classic) | Notes |
|--------|------------|----------------------|--------|
| POST | `/azure/chat/completions` | `{resource}/openai/deployments/{deployment}/chat/completions` | Body `model` = LibreChat **modelGroupMap** key |
| POST | `/azure/embeddings` | `{resource}/openai/deployments/{deployment}/embeddings` | Same |
| POST | `/azure/responses` | `{resource}/openai/v1/responses` | OpenAI **Responses** API on Azure |
| GET | `/azure/responses/:responseId` | `{resource}/openai/v1/responses/{id}` | **Query** `model=<modelGroupMap key>` required (no JSON body) |

**Serverless** groups use `baseURL` from config; paths are resolved relative to that base (see `resolveAzureChatCompletions.ts`).

## What LibreChat already supports elsewhere (not this router)

These use the normal UI / JWT flows and `endpoints.azureOpenAI` in `librechat.yaml`, not the Agent passthrough:

- **Chat UI** — Azure models in the conversation stack (`packages/api` OpenAI initialize, etc.)
- **Assistants** — Azure-backed assistants where configured (`api/server/controllers/assistants`)
- **STT** — Speech-to-text via Azure OpenAI deployment (`STTService` with `azureOpenAI` provider)
- **Agents OpenAI route** — `POST /api/agents/v1/chat/completions` targets **LibreChat agents** (`model` = agent id), not raw Azure

## What is not covered here

- **Images / audio / batch / files** and other Azure endpoints — not proxied; add new resolvers + routes if needed
- **Microsoft Entra (AAD)** at the passthrough hop — only **`api-key`** from mapped group config
- **Per-user Azure keys** in this passthrough — resolution is from **app config** (`modelGroupMap` / `groupMap`), not user-provided keys

## Configuration

`model` (POST body or GET query) must exist under `endpoints.azureOpenAI.modelGroupMap` in `librechat.yaml` (or merged app config). Resolution uses `mapModelToAzureConfig` from `librechat-data-provider`.

## Operational

- **`PROXY`**: forwarded to `fetch` via Undici `ProxyAgent` when set
- Rebuild after TS changes: `npm run build:api`
