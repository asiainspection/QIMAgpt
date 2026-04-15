/**
 * OpenAI Chat Completions → Azure OpenAI passthrough (no protocol conversion).
 *
 * POST /v1/azure/chat/completions — full path: /api/agents/v1/azure/chat/completions
 *
 * Request body matches OpenAI chat completions; `model` must be a LibreChat Azure model key.
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

module.exports = router;
