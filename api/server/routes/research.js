const express = require('express');
const { configMiddleware } = require('~/server/middleware');
const {
  createConversation,
  getConversation,
  getMessagesForConversation,
  submitMessage,
} = require('~/server/controllers/research');

const router = express.Router();

router.use(require('~/server/middleware/requireJwtAuth'));
router.use(configMiddleware);

/**
 * Create a new research conversation.
 * @route POST /api/research/conversations
 * @body { title?: string }
 * @returns { conversationId, title, endpoint }
 */
router.post('/conversations', createConversation);

/**
 * Get a research conversation.
 * @route GET /api/research/conversations/:conversationId
 */
router.get('/conversations/:conversationId', getConversation);

/**
 * Get messages for a research conversation.
 * @route GET /api/research/conversations/:conversationId/messages
 */
router.get('/conversations/:conversationId/messages', getMessagesForConversation);

/**
 * Submit a message: create user message, run Exa Research, create assistant message.
 * @route POST /api/research/conversations/:conversationId/messages
 * @body { text: string }
 * @returns { userMessage, assistantMessage, status }
 */
router.post('/conversations/:conversationId/messages', submitMessage);

module.exports = router;
