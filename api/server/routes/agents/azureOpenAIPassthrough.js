/**
 * OpenAI → Azure OpenAI passthrough (no protocol conversion).
 *
 * POST /v1/azure/chat/completions — Chat Completions
 * POST /v1/azure/embeddings      — Embeddings
 * POST /v1/azure/responses       — Responses API (create)
 * GET  /v1/azure/responses/:id   — Responses API (retrieve); query `model` required
 *
 * `model` in JSON body must be a LibreChat Azure model key from `librechat.yaml`.
 */
const express = require('express');
const { PermissionTypes, Permissions } = require('librechat-data-provider');
const { validateAgentApiKey, findUser } = require('~/models');
const { configMiddleware } = require('~/server/middleware');
const { getRoleByName } = require('~/models/Role');
const { generateCheckAccess, createRequireApiKeyAuth } = require('@librechat/api');

const router = express.Router();

const requireApiKeyAuth = createRequireApiKeyAuth({
  validateAgentApiKey,
  findUser,
});

const checkRemoteAgentsFeature = generateCheckAccess({
  permissionType: PermissionTypes.REMOTE_AGENTS,
  permissions: [Permissions.USE],
  getRoleByName,
});

router.use(requireApiKeyAuth);
router.use(configMiddleware);
router.use(checkRemoteAgentsFeature);

router.get('/azure/responses/:responseId', async (req, res) => {
  const { handleAzureOpenAIPassthroughGetResponse } = require('@librechat/api');
  if (typeof handleAzureOpenAIPassthroughGetResponse !== 'function') {
    return res.status(500).json({
      error: {
        type: 'server_error',
        message:
          'handleAzureOpenAIPassthroughGetResponse is missing from @librechat/api. From the repo root run: npm run build:api — then restart the backend.',
      },
    });
  }
  await handleAzureOpenAIPassthroughGetResponse(req, res, { fetchImpl: fetch });
});

router.post('/azure/chat/completions', async (req, res) => {
  const { handleAzureOpenAIPassthroughChatCompletions } = require('@librechat/api');
  if (typeof handleAzureOpenAIPassthroughChatCompletions !== 'function') {
    return res.status(500).json({
      error: {
        type: 'server_error',
        message:
          'handleAzureOpenAIPassthroughChatCompletions is missing from @librechat/api. From the repo root run: npm run build:api — then restart the backend.',
      },
    });
  }
  await handleAzureOpenAIPassthroughChatCompletions(req, res, { fetchImpl: fetch });
});

router.post('/azure/responses', async (req, res) => {
  const { handleAzureOpenAIPassthroughResponses } = require('@librechat/api');
  if (typeof handleAzureOpenAIPassthroughResponses !== 'function') {
    return res.status(500).json({
      error: {
        type: 'server_error',
        message:
          'handleAzureOpenAIPassthroughResponses is missing from @librechat/api. From the repo root run: npm run build:api — then restart the backend.',
      },
    });
  }
  await handleAzureOpenAIPassthroughResponses(req, res, { fetchImpl: fetch });
});

router.post('/azure/embeddings', async (req, res) => {
  const { handleAzureOpenAIPassthroughEmbeddings } = require('@librechat/api');
  if (typeof handleAzureOpenAIPassthroughEmbeddings !== 'function') {
    return res.status(500).json({
      error: {
        type: 'server_error',
        message:
          'handleAzureOpenAIPassthroughEmbeddings is missing from @librechat/api. From the repo root run: npm run build:api — then restart the backend.',
      },
    });
  }
  await handleAzureOpenAIPassthroughEmbeddings(req, res, { fetchImpl: fetch });
});

module.exports = router;
