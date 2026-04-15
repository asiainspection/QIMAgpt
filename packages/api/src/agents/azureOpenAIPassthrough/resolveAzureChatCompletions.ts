import { mapModelToAzureConfig } from 'librechat-data-provider';
import type { TAzureConfig } from 'librechat-data-provider';
import { genAzureEndpoint } from '~/utils/azure';

export interface AzureChatCompletionsTarget {
  url: string;
  headers: Record<string, string>;
}

function stripTrailingSlash(s: string): string {
  return s.replace(/\/$/, '');
}

/**
 * Resolves Azure OpenAI chat completions URL and headers for a model key from `librechat.yaml`.
 */
export function resolveAzureChatCompletionsForModel(
  modelName: string,
  azureEndpointConfig: TAzureConfig | undefined,
): AzureChatCompletionsTarget {
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

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'api-key': apiKey,
    ...(extraHeaders ?? {}),
  };

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
