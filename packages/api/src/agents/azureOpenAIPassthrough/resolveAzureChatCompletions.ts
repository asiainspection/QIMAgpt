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
  const version = azureOptions.azureOpenAIApiVersion ?? '';

  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const u = new URL('openai/v1/responses', `${stripTrailingSlash(baseURL)}/`);
    if (version) {
      u.searchParams.set('api-version', version);
    }
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  if (!instanceName || !version) {
    throw new Error(
      'Azure OpenAI Responses API requires instanceName and api version for non-serverless config.',
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
  const version = azureOptions.azureOpenAIApiVersion ?? '';
  const headers = azurePassthroughHeaders(apiKey, extraHeaders, false);

  const safeId = encodeURIComponent(responseId);

  if (serverless === true && baseURL) {
    const u = new URL(`openai/v1/responses/${safeId}`, `${stripTrailingSlash(baseURL)}/`);
    if (version) {
      u.searchParams.set('api-version', version);
    }
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  if (!instanceName || !version) {
    throw new Error(
      'Azure OpenAI Responses GET requires instanceName and api version for non-serverless config.',
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
  const version = azureOptions.azureOpenAIApiVersion ?? '';
  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const u = new URL('embeddings', `${stripTrailingSlash(baseURL)}/`);
    if (version) {
      u.searchParams.set('api-version', version);
    }
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  const deploymentName = azureOptions.azureOpenAIApiDeploymentName;
  if (!instanceName || !deploymentName || !version) {
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
  const version = azureOptions.azureOpenAIApiVersion ?? '';

  const headers = azurePassthroughHeaders(apiKey, extraHeaders, true);

  if (serverless === true && baseURL) {
    const u = new URL('chat/completions', `${stripTrailingSlash(baseURL)}/`);
    if (version) {
      u.searchParams.set('api-version', version);
    }
    return { url: u.toString(), headers };
  }

  const instanceName = azureOptions.azureOpenAIApiInstanceName;
  const deploymentName = azureOptions.azureOpenAIApiDeploymentName;
  if (!instanceName || !deploymentName || !version) {
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
