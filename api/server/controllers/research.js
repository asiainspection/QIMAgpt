const crypto = require('crypto');
const { logger } = require('@librechat/data-schemas');
const { Constants } = require('librechat-data-provider');
const {
  getConvo,
  saveConvo,
  getMessages,
  saveMessage,
} = require('~/models');
const { runExaResearch } = require('~/server/services/ExaResearch');

const RESEARCH_ENDPOINT = 'research';
const MAX_INSTRUCTIONS_LENGTH = 4096;

/**
 * Create a new research conversation.
 * POST /api/research/conversations
 * Body: { title?: string }
 * Returns: { conversationId, title, endpoint }
 */
async function createConversation(req, res) {
  try {
    const conversationId = crypto.randomUUID();
    const title = typeof req.body?.title === 'string' && req.body.title.trim()
      ? req.body.title.trim().slice(0, 100)
      : 'Deep Research';

    await saveConvo(req, {
      conversationId,
      endpoint: RESEARCH_ENDPOINT,
      title,
    }, { context: 'POST /api/research/conversations' });

    const convo = await getConvo(req.user.id, conversationId);
    res.status(201).json({
      conversationId: convo.conversationId,
      title: convo.title,
      endpoint: convo.endpoint,
    });
  } catch (err) {
    logger.error('[research createConversation]', err);
    res.status(500).json({ error: 'Failed to create research conversation' });
  }
}

/**
 * Get a research conversation. Ensures it belongs to user and is research type.
 * GET /api/research/conversations/:conversationId
 */
async function getConversation(req, res) {
  try {
    const { conversationId } = req.params;
    const convo = await getConvo(req.user.id, conversationId);
    if (!convo) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    if (convo.endpoint !== RESEARCH_ENDPOINT) {
      return res.status(403).json({ error: 'Not a research conversation' });
    }
    res.status(200).json(convo);
  } catch (err) {
    logger.error('[research getConversation]', err);
    res.status(500).json({ error: 'Failed to get conversation' });
  }
}

/**
 * Get messages for a research conversation.
 * GET /api/research/conversations/:conversationId/messages
 */
async function getMessagesForConversation(req, res) {
  try {
    const { conversationId } = req.params;
    const convo = await getConvo(req.user.id, conversationId);
    if (!convo) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    if (convo.endpoint !== RESEARCH_ENDPOINT) {
      return res.status(403).json({ error: 'Not a research conversation' });
    }
    const messages = await getMessages({ conversationId }, '-_id -__v -user');
    res.status(200).json(messages);
  } catch (err) {
    logger.error('[research getMessages]', err);
    res.status(500).json({ error: 'Failed to get messages' });
  }
}

/**
 * Submit a user message, run Exa Research, save user + assistant messages.
 * POST /api/research/conversations/:conversationId/messages
 * Body: { text: string }
 * Returns: { userMessage, assistantMessage }
 */
async function submitMessage(req, res) {
  try {
    const { conversationId } = req.params;
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    if (!text) {
      return res.status(400).json({ message: 'text is required' });
    }
    const instructions = text.slice(0, MAX_INSTRUCTIONS_LENGTH);

    const convo = await getConvo(req.user.id, conversationId);
    if (!convo) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    if (convo.endpoint !== RESEARCH_ENDPOINT) {
      return res.status(403).json({ error: 'Not a research conversation' });
    }

    const apiKey = process.env.EXA_API_KEY;
    if (!apiKey || !apiKey.length) {
      logger.warn('[research submitMessage] EXA_API_KEY not configured');
      return res.status(503).json({
        message: 'Deep Research is not configured. Set EXA_API_KEY in the server environment.',
      });
    }

    const existingMessages = await getMessages({ conversationId }, 'messageId');
    const lastMessageId = Array.isArray(existingMessages) && existingMessages.length > 0
      ? existingMessages[existingMessages.length - 1].messageId
      : null;
    const parentMessageId = lastMessageId ?? Constants.NO_PARENT;

    const userMessageId = crypto.randomUUID();
    const assistantMessageId = crypto.randomUUID();

    const userMessagePayload = {
      messageId: userMessageId,
      conversationId,
      sender: 'User',
      text: instructions,
      isCreatedByUser: true,
      parentMessageId,
      endpoint: RESEARCH_ENDPOINT,
    };

    const savedUserMessage = await saveMessage(
      req,
      userMessagePayload,
      { context: 'POST /api/research/conversations/:id/messages (user)' },
    );
    if (!savedUserMessage) {
      return res.status(400).json({ error: 'Failed to save user message' });
    }

    let report = '';
    let status = 'completed';
    try {
      const result = await runExaResearch(apiKey, instructions);
      report = typeof result.report === 'string' ? result.report : String(result.report ?? '');
      status = result.status ?? 'completed';
    } catch (exaErr) {
      logger.error('[research submitMessage] Exa Research error', exaErr);
      const msg = exaErr.response?.data?.message ?? exaErr.response?.data?.error ?? exaErr.message ?? 'Exa Research failed';
      report = `Research failed: ${msg}`;
      status = 'failed';
    }

    const assistantMessagePayload = {
      messageId: assistantMessageId,
      conversationId,
      sender: 'Deep Research',
      text: report,
      isCreatedByUser: false,
      parentMessageId: userMessageId,
      endpoint: RESEARCH_ENDPOINT,
    };

    const savedAssistantMessage = await saveMessage(
      req,
      assistantMessagePayload,
      { context: 'POST /api/research/conversations/:id/messages (assistant)' },
    );
    if (!savedAssistantMessage) {
      return res.status(400).json({ error: 'Failed to save assistant message' });
    }

    await saveConvo(req, savedAssistantMessage, {
      context: 'POST /api/research/conversations/:id/messages (saveConvo)',
    });

    res.status(201).json({
      userMessage: savedUserMessage,
      assistantMessage: savedAssistantMessage,
      status,
    });
  } catch (err) {
    logger.error('[research submitMessage]', err);
    res.status(500).json({ error: 'Failed to submit research message' });
  }
}

module.exports = {
  createConversation,
  getConversation,
  getMessagesForConversation,
  submitMessage,
};
