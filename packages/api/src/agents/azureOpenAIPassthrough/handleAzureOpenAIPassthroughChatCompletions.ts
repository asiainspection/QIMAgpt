import type { Response as ExpressResponse } from 'express';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { ProxyAgent } from 'undici';
import { EModelEndpoint } from 'librechat-data-provider';
import { logger } from '@librechat/data-schemas';
import type { ServerRequest } from '~/types/http';
import type { AzurePassthroughTarget } from './resolveAzureChatCompletions';
import {
  resolveAzureChatCompletionsForModel,
  resolveAzureEmbeddingsForModel,
  resolveAzureOpenAIGetResponseForModel,
  resolveAzureOpenAIResponsesForModel,
} from './resolveAzureChatCompletions';

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

async function passthroughGetFromAzure(
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
  target: AzurePassthroughTarget,
  logPrefix: string,
): Promise<void> {
  const dispatcher = getDispatcher();
  const fetchInit: RequestInit = {
    method: 'GET',
    headers: target.headers,
    ...(dispatcher ? { dispatcher } : {}),
  };

  let upstreamFetch: Awaited<ReturnType<typeof fetch>>;
  try {
    upstreamFetch = await deps.fetchImpl(target.url, fetchInit);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`${logPrefix} Fetch failed: ${msg}`);
    res.status(502).json({
      error: {
        message: `Upstream request failed: ${msg}`,
        type: 'api_error',
      },
    });
    return;
  }

  const text = await upstreamFetch.text();
  forwardResponseContentType(res, upstreamFetch);
  res.status(upstreamFetch.status).send(text);
}

async function passthroughPostToAzure(
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
  target: AzurePassthroughTarget,
  bodyRaw: JsonObject,
  logPrefix: string,
): Promise<void> {
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
    logger.error(`${logPrefix} Fetch failed: ${msg}`);
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
    logger.error(`${logPrefix} Stream pipe failed: ${msg}`);
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

function readPassthroughBody(req: ServerRequest): JsonObject | null {
  const rawBody: unknown = req.body;
  if (!isRecord(rawBody)) {
    return null;
  }
  return rawBody;
}

/**
 * POST: OpenAI Chat Completions body → Azure (same shape in / out).
 * `model` must match a LibreChat Azure `modelGroupMap` key.
 */
export async function handleAzureOpenAIPassthroughChatCompletions(
  req: ServerRequest,
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
): Promise<void> {
  const azureCfg = req.config?.endpoints?.[EModelEndpoint.azureOpenAI];
  const bodyRaw = readPassthroughBody(req);
  if (!bodyRaw) {
    res.status(400).json({
      error: {
        message: 'JSON body required.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

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

  let target: AzurePassthroughTarget;
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

  await passthroughPostToAzure(res, deps, target, bodyRaw, '[azureOpenAIPassthrough]');
}

/**
 * POST: OpenAI Responses API body → Azure `openai/v1/responses` (same shape in / out).
 * `model` must match a LibreChat Azure `modelGroupMap` key (used for credentials / api-version).
 */
export async function handleAzureOpenAIPassthroughResponses(
  req: ServerRequest,
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
): Promise<void> {
  const azureCfg = req.config?.endpoints?.[EModelEndpoint.azureOpenAI];
  const bodyRaw = readPassthroughBody(req);
  if (!bodyRaw) {
    res.status(400).json({
      error: {
        message: 'JSON body required.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

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

  let target: AzurePassthroughTarget;
  try {
    target = resolveAzureOpenAIResponsesForModel(modelName.trim(), azureCfg);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough:responses] Azure resolve failed: ${msg}`);
    res.status(503).json({
      error: {
        message: msg,
        type: 'api_error',
      },
    });
    return;
  }

  await passthroughPostToAzure(res, deps, target, bodyRaw, '[azureOpenAIPassthrough:responses]');
}

/**
 * GET: poll/retrieve OpenAI Responses object from Azure (`GET .../openai/v1/responses/{id}`).
 * Query `model` (LibreChat Azure model key) is required to resolve credentials.
 */
export async function handleAzureOpenAIPassthroughGetResponse(
  req: ServerRequest,
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
): Promise<void> {
  const azureCfg = req.config?.endpoints?.[EModelEndpoint.azureOpenAI];

  const params = req.params as Record<string, string | undefined>;
  const idRaw = params.responseId;
  if (typeof idRaw !== 'string' || idRaw.length === 0) {
    res.status(400).json({
      error: {
        message: 'Missing response id in path.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

  const modelRaw = req.query.model;
  if (typeof modelRaw !== 'string' || modelRaw.trim() === '') {
    res.status(400).json({
      error: {
        message:
          'Query parameter `model` is required (LibreChat Azure model key from `modelGroupMap`).',
        type: 'invalid_request_error',
      },
    });
    return;
  }

  let target: AzurePassthroughTarget;
  try {
    target = resolveAzureOpenAIGetResponseForModel(modelRaw.trim(), idRaw, azureCfg);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough:responses:get] Azure resolve failed: ${msg}`);
    res.status(503).json({
      error: {
        message: msg,
        type: 'api_error',
      },
    });
    return;
  }

  await passthroughGetFromAzure(res, deps, target, '[azureOpenAIPassthrough:responses:get]');
}

/**
 * POST: OpenAI Embeddings body → Azure `embeddings` (same shape in / out).
 */
export async function handleAzureOpenAIPassthroughEmbeddings(
  req: ServerRequest,
  res: ExpressResponse,
  deps: HandleAzureOpenAIPassthroughDeps,
): Promise<void> {
  const azureCfg = req.config?.endpoints?.[EModelEndpoint.azureOpenAI];
  const bodyRaw = readPassthroughBody(req);
  if (!bodyRaw) {
    res.status(400).json({
      error: {
        message: 'JSON body required.',
        type: 'invalid_request_error',
      },
    });
    return;
  }

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

  let target: AzurePassthroughTarget;
  try {
    target = resolveAzureEmbeddingsForModel(modelName.trim(), azureCfg);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error(`[azureOpenAIPassthrough:embeddings] Azure resolve failed: ${msg}`);
    res.status(503).json({
      error: {
        message: msg,
        type: 'api_error',
      },
    });
    return;
  }

  await passthroughPostToAzure(res, deps, target, bodyRaw, '[azureOpenAIPassthrough:embeddings]');
}
