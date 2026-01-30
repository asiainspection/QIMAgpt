const axios = require('axios');
const { logger } = require('@librechat/data-schemas');

const EXA_RESEARCH_BASE = 'https://api.exa.ai/research/v1';
const POLL_INTERVAL_MS = 3000;
const MAX_POLL_MS = 300000; // 5 minutes

/**
 * Create an Exa Research task and poll until completed or failed.
 * @param {string} apiKey - EXA_API_KEY
 * @param {string} instructions - Natural-language research instructions (max 4096 chars)
 * @param {object} [options] - Optional: { model: 'exa-research'|'exa-research-pro', outputSchema }
 * @returns {Promise<{ report: string, status: string }>} - report is markdown or JSON string; status 'completed' or 'failed'
 */
async function runExaResearch(apiKey, instructions, options = {}) {
  if (!apiKey || typeof instructions !== 'string' || !instructions.trim()) {
    throw new Error('Exa Research requires apiKey and non-empty instructions');
  }
  const trimmed = instructions.trim().slice(0, 4096);
  const model = options.model || 'exa-research';
  const body = { instructions: trimmed, model };
  if (options.outputSchema) {
    body.outputSchema = options.outputSchema;
  }

  const createRes = await axios.post(EXA_RESEARCH_BASE, body, {
    headers: {
      'x-api-key': apiKey,
      'Content-Type': 'application/json',
    },
    timeout: 15000,
  });

  const researchId = createRes.data?.researchId;
  if (!researchId) {
    throw new Error('Exa Research create did not return researchId');
  }

  const startedAt = Date.now();
  for (;;) {
    if (Date.now() - startedAt > MAX_POLL_MS) {
      throw new Error('Exa Research timed out waiting for completion');
    }
    const getRes = await axios.get(`${EXA_RESEARCH_BASE}/${researchId}`, {
      headers: { 'x-api-key': apiKey },
      timeout: 10000,
    });
    const data = getRes.data;
    const status = data?.status;

    if (status === 'completed') {
      const candidate = data.answer ?? data.result ?? data.output ?? data.report ?? data;
      let report = candidate;
      if (report && typeof report === 'object') {
        report = report.content ?? report.report ?? report.answer ?? JSON.stringify(report);
      } else if (typeof report === 'string') {
        try {
          const parsed = JSON.parse(report);
          if (parsed && typeof parsed === 'object') {
            report = parsed.content ?? parsed.report ?? parsed.answer ?? report;
          }
        } catch (_err) {
          /* keep original string */
        }
      }
      return { report: report || '(No content)', status: 'completed' };
    }
    if (status === 'failed' || status === 'canceled') {
      const errMsg = data.errorMessage ?? data.message ?? status;
      logger.warn(`[ExaResearch] Task ${researchId} ${status}: ${errMsg}`);
      return {
        report: `Research ${status}: ${errMsg}`,
        status: status === 'canceled' ? 'canceled' : 'failed',
      };
    }

    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

module.exports = { runExaResearch };
