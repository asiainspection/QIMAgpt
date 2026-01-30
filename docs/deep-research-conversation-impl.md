# 深度研究会话页面 — 实现分析

## 需求拆解

1. **单独深度研究会话页面**：独立于普通对话和 Agent，有自己的一级入口（与「对话」「Agent」同级），形态是「消息列表 + 输入框」的会话页。
2. **类普通对话的交互**：用户发送后立刻看到自己的消息气泡；等待期间有明确提示「正在研究…」（类似普通对话的「正在输入」）；结果返回后以助手消息形式展示。
3. **基于结果继续对话**：研究报告作为一条助手消息展示后，用户可继续输入；下一轮可以是「再跑一次深度研究」或「基于已有报告用模型回答」。

---

## 方案对比

| 方案 | 思路 | 优点 | 缺点 |
|------|------|------|------|
| **A. 复用现有 Chat 管线** | 增加虚拟 endpoint（如 `research`），发消息时后端跑 Exa、写回一条 assistant 消息，前端仍走 ChatView + 现有消息 API | 复用 ChatView、对话列表、消息持久化、isSubmitting 等状态 | 需在现有 chat 后端分支「research」逻辑；research 非流式，与普通 chat 的流式/SSE 不一致，要兼容 |
| **B. 独立研究会话前端 + 专用 API** | 独立页面（ResearchChatView），UI 复用消息列表 + 输入框；专用「研究会话」API：创建会话、发消息触发 Exa、写回 assistant 消息 | 与主对话解耦，逻辑清晰；可先只做「多轮 Exa」，再扩展「基于报告 + LLM 续写」 | 需实现研究会话与消息的持久化（新 API 或复用 Conversation 加 type） |
| **C. 复用 Conversation/Message，后端按 endpoint 分支** | 新建会话时 `endpoint = 'research'`；提交消息时后端根据 endpoint 调 Exa 而非 LLM，写入同一套 Message | 前端几乎不改，对话列表统一 | 后端 chat 入口要分支；research 非流式，与现有 submission/SSE 模型不一致，改动面大 |

---

## 推荐：方案 B（独立研究会话 + 专用 API）

### 1. 路由与入口

- **路由**：`/research`（新会话）、`/research/c/:conversationId`（已有研究会话）。
- **导航**：保持现有「深度研究」入口（侧栏按钮 /research）；在侧栏或 research 页内增加「新研究会话」+「研究会话列表」（可选，与普通对话列表类似）。

### 2. 前端结构

- **ResearchChatView**（新建，可参考 ChatView）：
  - **顶部**：标题「深度研究」。
  - **中间**：消息列表，与现有 `MessagesView` 一致或复用 — 展示 `messagesTree`（user / assistant 气泡）；每条 assistant 为研究报告，用现有 Markdown 渲染。
  - **底部**：输入框，复用 `ChatForm` 或同款（无文件/预设等可做精简）。
- **状态与数据流**：
  - 当前 `conversationId`（research 会话 ID）。
  - `messages` 来自：`GET /api/research/conversations/:id/messages`（或复用现有 messages API 且带 `endpoint=research` 的会话）。
  - 发送时：
    1. **乐观更新**：先在前端追加一条 user 消息到列表。
    2. **进行中状态**：在列表末尾展示一条「虚拟」进行中消息（例如 `messageId: 'temp-research', text: '', inProgress: true`），UI 显示 Spinner +「正在研究…」（与普通对话的「正在输入」一致）。
    3. 请求：`POST /api/research/conversations/:id/messages` 或「先 POST exa-research，再 POST messages 写 user+assistant」。
    4. **收到结果**：去掉进行中占位，追加真实 assistant 消息（报告正文），并刷新消息列表（或由服务端返回完整新消息列表）。
- **「正在研究」的 UI**：与普通对话一致 — 在消息列表末尾渲染一条「进行中」消息（如现有 `latestMessage` + `isSubmitting` 的占位），展示 Spinner 和「正在研究…」文案；结果返回后替换为正式 assistant 消息。

### 3. 后端

- **研究会话与消息持久化**（二选一或组合）：
  - **复用现有模型**：用 `Conversation` + `Message`，通过 `conversation.endpoint === 'research'`（或 `endpointType`）区分；创建 research 会话时设好 endpoint，拉取消息时仍用现有 `GET /api/messages/:conversationId`。
  - **专用 API**：例如 `POST /api/research/conversations`（创建）、`GET /api/research/conversations/:id/messages`、`POST /api/research/conversations/:id/messages`（发 user 消息并触发 Exa，写回 assistant 消息）。
- **发消息并触发研究**：
  - 单接口：`POST /api/research/conversations/:id/messages`，body `{ text }` → 后端创建 user message，调 `runExaResearch(text)`，创建 assistant message 写入 report，返回 assistant 消息（或完整 messages）。
  - 或保持现有：`POST /api/agents/exa-research` 只返回报告，前端再调 `POST /api/messages` 写 user + assistant（需后端支持 research 会话的 message 创建与 conversationId 归属）。
- **基于结果继续对话**：
  - **多轮 Exa**：每次用户发送都当作新的 research 指令，继续调 Exa，新报告作为新的 assistant 消息追加；可选把上一轮报告摘要放进下一轮 `instructions` 以增强上下文。
  - **多轮 Exa + LLM 续写**（可选）：在研究会话中，用户第二条及之后的消息可走现有 chat 接口，把当前会话的 messages（含研究报告）作为 context 发给 LLM，流式返回；需后端识别 research 会话并在第二 turn 起走 chat 分支。

### 4. 实现步骤摘要

| 步骤 | 后端 | 前端 |
|------|------|------|
| 1 | 确定 research 会话存储（复用 Conversation + endpoint=research，或新表）；实现「创建 research 会话」「按 conversationId 拉取 messages」 | 新增路由 `/research`、`/research/c/:conversationId`，渲染 ResearchChatView |
| 2 | 实现「提交用户消息并触发 Exa」：写 user message，调 `runExaResearch(text)`，写 assistant message，返回 | ResearchChatView：消息列表（复用或仿 MessagesView）+ 输入框；发送时乐观更新 user + 显示「正在研究…」占位；调新 API；收到结果后更新列表 |
| 3 | 若需「基于结果继续」用 LLM：在 research 会话第二 turn 起调用现有 chat completion，传入历史 messages | 可选：在 research 页提供「继续用模型回答」开关，或默认第二 turn 起走 LLM |

### 5. 与现有组件的复用

- **消息列表**：`MessagesView` + `buildTree` 依赖 `messagesTree` 和 `conversationId`；ResearchChatView 可传入 research 会话的 messages 与 conversationId，复用同一套 Message / MessageContent / Markdown 渲染。
- **进行中状态**：普通对话用 `latestMessage` + `isSubmitting` + submission 流；Research 可维护本地 `isResearching` + 一条临时 `latestMessage`（无 content、仅作占位），UI 上复用类似 InProgressCall / Spinner 的展示。
- **输入框**：复用 `ChatForm` 或抽一层仅保留 text 输入 + 提交，提交时调用 research 专用 handler（不调 `ask()`）。

---

## 小结

- **单独深度研究会话页面**：通过独立路由 `/research`、`/research/c/:id` 和 ResearchChatView 实现，与普通对话、Agent 同级。
- **研究时的交互**：发消息后立刻展示用户气泡，再展示「正在研究…」占位（与普通对话等待回复一致），结果返回后展示助手气泡（报告 Markdown）。
- **基于结果继续对话**：报告作为助手消息持久化；下一轮可继续触发 Exa（多轮研究）或走 LLM（基于报告续写），由后端根据会话类型与配置分支即可。

整体采用「独立研究会话 + 专用 API」的方案 B，在保持与现有 Chat 体验一致的前提下，改动集中、可分批实现（先多轮 Exa，再选做 LLM 续写）。
