const crypto = require('crypto');
const { logger } = require('@librechat/data-schemas');
const { Constants } = require('librechat-data-provider');
const { runExaResearch } = require('~/server/services/ExaResearch');
const { getConvo, saveConvo, getMessages, saveMessage } = require('~/models');

const MAX_INSTRUCTIONS_LENGTH = 4096;

/**
 * POST /api/agents/exa-research
 * Body: { instructions: string }
 * Returns: { report: string, status: string } or error
 */
async function exaResearch(req, res) {
  try {
    const instructions = req.body?.instructions;
    if (typeof instructions !== 'string' || !instructions.trim()) {
      return res.status(400).json({ message: 'instructions (string) is required' });
    }
    const trimmed = instructions.trim().slice(0, MAX_INSTRUCTIONS_LENGTH);

    const apiKey = process.env.EXA_API_KEY;
    if (!apiKey || !apiKey.length) {
      logger.warn('[exaResearch] EXA_API_KEY not configured');
      return res.status(503).json({
        message: 'Deep Research is not configured. Set EXA_API_KEY in the server environment.',
      });
    }

    const { report, status } = await runExaResearch(apiKey, trimmed);
    return res.status(200).json({ report, status });
  } catch (err) {
    logger.error('[exaResearch]', err);
    const status = err.response?.status;
    const message =
      err.response?.data?.message ?? err.response?.data?.error ?? err.message ?? 'Exa Research failed';
    if (status === 401) {
      return res.status(503).json({ message: 'Invalid EXA_API_KEY' });
    }
    if (status === 429) {
      return res.status(429).json({ message: 'Exa rate limit exceeded' });
    }
    return res.status(status && status >= 400 && status < 600 ? status : 500).json({ message });
  }
}

/**
 * POST /api/agents/exa-research-in-conversation
 * Body: { conversationId: string, text: string }
 * Runs Exa Research and appends user + assistant messages to the given (any) conversation.
 * Returns: { userMessage, assistantMessage, status }
 */
async function exaResearchInConversation(req, res) {
  try {
    const conversationId = req.body?.conversationId;
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    if (!conversationId || !text) {
      return res.status(400).json({ message: 'conversationId and text are required' });
    }
    const instructions = text.slice(0, MAX_INSTRUCTIONS_LENGTH);

    const convo = await getConvo(req.user.id, conversationId);
    if (!convo) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    const apiKey = process.env.EXA_API_KEY;
    if (!apiKey || !apiKey.length) {
      logger.warn('[exaResearchInConversation] EXA_API_KEY not configured');
      return res.status(503).json({
        message: 'Deep Research is not configured. Set EXA_API_KEY in the server environment.',
      });
    }

    const existingMessages = await getMessages({ conversationId }, 'messageId');
    const lastMessageId = Array.isArray(existingMessages) && existingMessages.length > 0
      ? existingMessages[existingMessages.length - 1].messageId
      : null;
    const parentMessageId = lastMessageId ?? Constants.NO_PARENT;
    const endpoint = convo.endpoint ?? 'openAI';

    const userMessageId = crypto.randomUUID();
    const assistantMessageId = crypto.randomUUID();

    const userMessagePayload = {
      messageId: userMessageId,
      conversationId,
      sender: 'User',
      text: instructions,
      isCreatedByUser: true,
      parentMessageId,
      endpoint,
    };

    const savedUserMessage = await saveMessage(
      req,
      userMessagePayload,
      { context: 'POST /api/agents/exa-research-in-conversation (user)' },
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
      logger.error('[exaResearchInConversation] Exa Research error', exaErr);
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
      endpoint,
    };

    const savedAssistantMessage = await saveMessage(
      req,
      assistantMessagePayload,
      { context: 'POST /api/agents/exa-research-in-conversation (assistant)' },
    );
    if (!savedAssistantMessage) {
      return res.status(400).json({ error: 'Failed to save assistant message' });
    }

    await saveConvo(req, savedAssistantMessage, {
      context: 'POST /api/agents/exa-research-in-conversation (saveConvo)',
    });

    return res.status(201).json({
      userMessage: savedUserMessage,
      assistantMessage: savedAssistantMessage,
      status,
    });
  } catch (err) {
    logger.error('[exaResearchInConversation]', err);
    return res.status(500).json({ error: 'Failed to run research in conversation' });
  }
}

module.exports = { exaResearch, exaResearchInConversation };
