const { logger } = require('@librechat/data-schemas');
const { runExaResearch } = require('~/server/services/ExaResearch');

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

module.exports = { exaResearch };
