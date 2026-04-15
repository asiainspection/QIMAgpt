import type { Response as ExpressResponse } from 'express';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { ProxyAgent } from 'undici';
import { EModelEndpoint } from 'librechat-data-provider';
import { logger } from '@librechat/data-schemas';
import type { ServerRequest } from '~/types/http';
import { resolveAzureChatCompletionsForModel } from './resolveAzureChatCompletions';

type JsonObject = Record<string, unknown>;

function isRecord(v: unknown): v is JsonObject {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export interface HandleAzureOpenAIPassthroughDeps {
  fetchImpl: typeof fetch;
}

function getDispatcher(): ProxyAgent | undefined {
  const proxy = process.env.PROXY;
  if (!proxy || proxy.trim() === '') {
    return undefined;
  }
  return new ProxyAgent(proxy);
}

function forwardResponseContentType(
  res: ExpressResponse,
  upstream: Awaited<ReturnType<typeof fetch>>,
): void {
  const ct = upstream.headers.get('content-type');
  if (ct) {
    res.setHeader('Content-Type', ct);
  }
}

/**
 * POST handler: OpenAI Chat Completions body → Azure OpenAI (same shape in / out).
 * `model` must match a key in LibreChat Azure `modelGroupMap`.
 */
export async function handleAzureOpenAIPassthroughChatCompletions(
  req: ServerRequest,
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
): Promise<void> {
  const azureCfg = req.config?.endpoints?.[EModelEndpoint.azureOpenAI];

  const rawBody: unknown = req.body;
  if (!isRecord(rawBody)) {
    res.status(400).json({
      error: {
        message: 'JSON body required.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

  const bodyRaw = rawBody;

  const modelName = bodyRaw.model;
  if (typeof modelName !== 'string' || modelName.trim() === '') {
    res.status(400).json({
      error: {
        message: '`model` is required and must be a non-empty string.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

  let target: ReturnType<typeof resolveAzureChatCompletionsForModel>;
  try {
    target = resolveAzureChatCompletionsForModel(modelName.trim(), azureCfg);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough] Azure resolve failed: ${msg}`);
    res.status(503).json({
      error: {
        message: msg,
        type: 'api_error',
      },
    });
    return;
  }

  const stream = bodyRaw.stream === true;
  const dispatcher = getDispatcher();

  const fetchInit: RequestInit = {
    method: 'POST',
    headers: target.headers,
    body: JSON.stringify(bodyRaw),
    ...(dispatcher ? { dispatcher } : {}),
  };

  let upstreamFetch: Awaited<ReturnType<typeof fetch>>;
  try {
    upstreamFetch = await deps.fetchImpl(target.url, fetchInit);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough] Fetch failed: ${msg}`);
    res.status(502).json({
      error: {
        message: `Upstream request failed: ${msg}`,
        type: 'api_error',
      },
    });
    return;
  }

  if (!upstreamFetch.body) {
    const errText = upstreamFetch.ok ? '' : await upstreamFetch.text();
    if (!upstreamFetch.ok) {
      forwardResponseContentType(res, upstreamFetch);
      res.status(upstreamFetch.status).send(errText);
      return;
    }
    res.status(502).json({
      error: {
        message: 'Empty upstream response body.',
        type: 'api_error',
      },
    });
    return;
  }

  if (!stream) {
    const text = await upstreamFetch.text();
    forwardResponseContentType(res, upstreamFetch);
    res.status(upstreamFetch.status).send(text);
    return;
  }

  if (!upstreamFetch.ok) {
    const errText = await upstreamFetch.text();
    forwardResponseContentType(res, upstreamFetch);
    res.status(upstreamFetch.status).send(errText);
    return;
  }

  res.setHeader(
    'Content-Type',
    upstreamFetch.headers.get('content-type') ?? 'text/event-stream; charset=utf-8',
  );
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  try {
    const webStream = upstreamFetch.body as unknown as import('stream/web').ReadableStream;
    const nodeStream = Readable.fromWeb(webStream);
    await pipeline(nodeStream, res);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough] Stream pipe failed: ${msg}`);
    if (!res.headersSent) {
      res.status(502).json({
        error: {
          message: msg,
          type: 'api_error',
        },
      });
    }
  }
}
