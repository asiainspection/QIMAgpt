import { mapModelToAzureConfig } from 'librechat-data-provider';
import type { TAzureConfig } from 'librechat-data-provider';
import { genAzureEndpoint } from '~/utils/azure';

export interface AzurePassthroughTarget {
  url: string;
  headers: Record<string, string>;
}

/** @deprecated Use {@link AzurePassthroughTarget} */
export type AzureChatCompletionsTarget = AzurePassthroughTarget;

function stripTrailingSlash(s: string): string {
  return s.replace(/\/$/, '');
}

type PassthroughApiKind = 'responses' | 'chatOrEmbeddings';

/**
 * Resolves `api-version` for passthrough URLs. Azure rejects versions that do not support the
 * route (e.g. `/openai/v1/responses` often needs a newer preview than legacy chat).
 *
 * Precedence: `AZURE_OPENAI_PASSTHROUGH_API_VERSION` → kind-specific env → YAML `version`.
 *
 * - `AZURE_OPENAI_PASSTHROUGH_API_VERSION` — all passthrough routes
 * - `AZURE_OPENAI_RESPONSES_API_VERSION` — POST/GET `/openai/v1/responses` only
 * - `AZURE_OPENAI_CHAT_API_VERSION` — chat completions + embeddings only
 */
export function effectivePassthroughApiVersion(
  mappedVersion: string,
  kind: PassthroughApiKind,
): string {
  const global = process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION?.trim();
  if (global) {
    return global;
  }
  if (kind === 'responses') {
    const r = process.env.AZURE_OPENAI_RESPONSES_API_VERSION?.trim();
    if (r) {
      return r;
    }
  } else {
    const c = process.env.AZURE_OPENAI_CHAT_API_VERSION?.trim();
    if (c) {
      return c;
    }
  }
  return mappedVersion;
}

function azurePassthroughHeaders(
  apiKey: string,
  extraHeaders: Record<string, string> | undefined,
  includeJsonContentType: boolean,
): Record<string, string> {
  const headers: Record<string, string> = {
    'api-key': apiKey,
    ...(extraHeaders ?? {}),
  };
  if (includeJsonContentType) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
}

function azureOpenAiResourceOrigin(instanceName: string): string {
  const trimmed = instanceName.trim();
  if (trimmed.includes('.azure.com')) {
    return `https://${trimmed.replace(/^https?:\/\//i, '')}`;
  }
  return `https://${trimmed}.openai.azure.com`;
}

/** True when `baseURL` is already the Foundry / v1 root (…/openai/v1), so paths are relative segments only. */
function serverlessBaseEndsWithOpenAiV1(baseURL: string): boolean {
  return /\/openai\/v1$/i.test(stripTrailingSlash(baseURL));
}

function appendApiVersionQuery(u: URL, version: string): void {
  if (version.trim().length > 0) {
    u.searchParams.set('api-version', version);
  }
}

/**
 * Azure OpenAI Responses API (`POST /openai/v1/responses`), per Microsoft Foundry docs.
 * Differs from chat completions URL shape (no `deployments/{id}/chat/completions` segment).
 */
export function resolveAzureOpenAIResponsesForModel(
  modelName: string,
  azureEndpointConfig: TAzureConfig | undefined,
): AzurePassthroughTarget {
  if (!azureEndpointConfig?.modelGroupMap || !azureEndpointConfig?.groupMap) {
    throw new Error('Azure OpenAI endpoint is not configured.');
  }

  const {
    azureOptions,
    baseURL,
    serverless,
    headers: extraHeaders,
  } = mapModelToAzureConfig({
    modelName,
    modelGroupMap: azureEndpointConfig.modelGroupMap,
    groupMap: azureEndpointConfig.groupMap,
  });

  const apiKey = azureOptions.azureOpenAIApiKey;
  const mappedVersion = azureOptions.azureOpenAIApiVersion ?? '';
  const version = effectivePassthroughApiVersion(mappedVersion, 'responses');

  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const root = `${stripTrailingSlash(baseURL)}/`;
    const relativePath = serverlessBaseEndsWithOpenAiV1(baseURL) ? 'responses' : 'openai/v1/responses';
    const u = new URL(relativePath, root);
    appendApiVersionQuery(u, version);
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  if (!instanceName || version.trim().length === 0) {
    throw new Error(
      'Azure OpenAI Responses API requires instanceName and api version (set `version` in librechat.yaml for this model group, or set AZURE_OPENAI_RESPONSES_API_VERSION / AZURE_OPENAI_PASSTHROUGH_API_VERSION).',
    );
  }

  const origin = azureOpenAiResourceOrigin(instanceName);
  const url = `${origin}/openai/v1/responses?api-version=${encodeURIComponent(version)}`;
  return { url, headers };
}

/**
 * GET Azure OpenAI Responses API: `/openai/v1/responses/{id}` (poll / retrieve).
 */
export function resolveAzureOpenAIGetResponseForModel(
  modelName: string,
  responseId: string,
  azureEndpointConfig: TAzureConfig | undefined,
): AzurePassthroughTarget {
  if (!azureEndpointConfig?.modelGroupMap || !azureEndpointConfig?.groupMap) {
    throw new Error('Azure OpenAI endpoint is not configured.');
  }

  const {
    azureOptions,
    baseURL,
    serverless,
    headers: extraHeaders,
  } = mapModelToAzureConfig({
    modelName,
    modelGroupMap: azureEndpointConfig.modelGroupMap,
    groupMap: azureEndpointConfig.groupMap,
  });

  const apiKey = azureOptions.azureOpenAIApiKey;
  const mappedVersion = azureOptions.azureOpenAIApiVersion ?? '';
  const version = effectivePassthroughApiVersion(mappedVersion, 'responses');
  const headers = azurePassthroughHeaders(apiKey, extraHeaders, false);

  const safeId = encodeURIComponent(responseId);

  if (serverless === true && baseURL) {
    const root = `${stripTrailingSlash(baseURL)}/`;
    const relativePath = serverlessBaseEndsWithOpenAiV1(baseURL)
      ? `responses/${safeId}`
      : `openai/v1/responses/${safeId}`;
    const u = new URL(relativePath, root);
    appendApiVersionQuery(u, version);
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  if (!instanceName || version.trim().length === 0) {
    throw new Error(
      'Azure OpenAI Responses GET requires instanceName and api version (set `version` in librechat.yaml, or AZURE_OPENAI_RESPONSES_API_VERSION / AZURE_OPENAI_PASSTHROUGH_API_VERSION).',
    );
  }

  const origin = azureOpenAiResourceOrigin(instanceName);
  const url = `${origin}/openai/v1/responses/${safeId}?api-version=${encodeURIComponent(version)}`;
  return { url, headers };
}

/**
 * Azure OpenAI embeddings: `deployments/{deployment}/embeddings` (classic) or serverless-relative `embeddings`.
 */
export function resolveAzureEmbeddingsForModel(
  modelName: string,
  azureEndpointConfig: TAzureConfig | undefined,
): AzurePassthroughTarget {
  if (!azureEndpointConfig?.modelGroupMap || !azureEndpointConfig?.groupMap) {
    throw new Error('Azure OpenAI endpoint is not configured.');
  }

  const {
    azureOptions,
    baseURL,
    serverless,
    headers: extraHeaders,
  } = mapModelToAzureConfig({
    modelName,
    modelGroupMap: azureEndpointConfig.modelGroupMap,
    groupMap: azureEndpointConfig.groupMap,
  });

  const apiKey = azureOptions.azureOpenAIApiKey;
  const mappedVersion = azureOptions.azureOpenAIApiVersion ?? '';
  const version = effectivePassthroughApiVersion(mappedVersion, 'chatOrEmbeddings');
  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const root = `${stripTrailingSlash(baseURL)}/`;
    const u = new URL('embeddings', root);
    appendApiVersionQuery(u, version);
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  const deploymentName = azureOptions.azureOpenAIApiDeploymentName;
  if (!instanceName || !deploymentName || version.trim().length === 0) {
    throw new Error(
      'Azure OpenAI embeddings require instanceName, deploymentName, and api version for non-serverless config.',
    );
  }

  const base = genAzureEndpoint({
    azureOpenAIApiInstanceName: instanceName,
    azureOpenAIApiDeploymentName: deploymentName,
  });
  const url = `${stripTrailingSlash(base)}/embeddings?api-version=${encodeURIComponent(version)}`;
  return { url, headers };
}

export function resolveAzureChatCompletionsForModel(
  modelName: string,
  azureEndpointConfig: TAzureConfig | undefined,
): AzurePassthroughTarget {
  if (!azureEndpointConfig?.modelGroupMap || !azureEndpointConfig?.groupMap) {
    throw new Error('Azure OpenAI endpoint is not configured.');
  }

  const {
    azureOptions,
    baseURL,
    serverless,
    headers: extraHeaders,
  } = mapModelToAzureConfig({
    modelName,
    modelGroupMap: azureEndpointConfig.modelGroupMap,
    groupMap: azureEndpointConfig.groupMap,
  });

  const apiKey = azureOptions.azureOpenAIApiKey;
  const mappedVersion = azureOptions.azureOpenAIApiVersion ?? '';
  const version = effectivePassthroughApiVersion(mappedVersion, 'chatOrEmbeddings');

  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const root = `${stripTrailingSlash(baseURL)}/`;
    const u = new URL('chat/completions', root);
    appendApiVersionQuery(u, version);
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  const deploymentName = azureOptions.azureOpenAIApiDeploymentName;
  if (!instanceName || !deploymentName || version.trim().length === 0) {
    throw new Error(
      'Azure OpenAI requires instanceName, deploymentName, and api version for non-serverless config.',
    );
  }

  const base = genAzureEndpoint({
    azureOpenAIApiInstanceName: instanceName,
    azureOpenAIApiDeploymentName: deploymentName,
  });
  const url = `${stripTrailingSlash(base)}/chat/completions?api-version=${encodeURIComponent(version)}`;
  return { url, headers };
}
