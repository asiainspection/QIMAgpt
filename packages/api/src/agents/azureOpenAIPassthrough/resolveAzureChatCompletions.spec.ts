import type { TAzureConfig } from 'librechat-data-provider';
import {
  resolveAzureChatCompletionsForModel,
  resolveAzureEmbeddingsForModel,
  resolveAzureOpenAIGetResponseForModel,
  resolveAzureOpenAIResponsesForModel,
} from './resolveAzureChatCompletions';

describe('resolveAzureOpenAIResponsesForModel', () => {
  it('builds openai/v1/responses URL for a configured model', () => {
    const cfg = {
      modelGroupMap: {
        'gpt-5.4': { group: 'g1' },
      },
      groupMap: {
        g1: {
          instanceName: 'my-instance',
          apiKey: 'test-key',
          version: '2025-01-01-preview',
          models: {
            'gpt-5.4': {
              deploymentName: 'gpt-5.4',
              version: '2025-01-01-preview',
            },
          },
        },
      },
    } as unknown as TAzureConfig;

    const { url, headers } = resolveAzureOpenAIResponsesForModel('gpt-5.4', cfg);
    expect(url).toContain('my-instance.openai.azure.com');
    expect(url).toContain('/openai/v1/responses');
    expect(url).toContain('api-version=2025-01-01-preview');
    expect(headers['api-key']).toBe('test-key');
  });

  it('builds GET response URL with encoded id', () => {
    const cfg = {
      modelGroupMap: { 'gpt-5.4': { group: 'g1' } },
      groupMap: {
        g1: {
          instanceName: 'my-instance',
          apiKey: 'k',
          version: '2025-01-01-preview',
          models: {
            'gpt-5.4': { deploymentName: 'gpt-5.4', version: '2025-01-01-preview' },
          },
        },
      },
    } as unknown as TAzureConfig;

    const { url, headers } = resolveAzureOpenAIGetResponseForModel('gpt-5.4', 'resp_abc', cfg);
    expect(url).toContain('/openai/v1/responses/resp_abc');
    expect(url).toContain('api-version=');
    expect(headers['Content-Type']).toBeUndefined();
    expect(headers['api-key']).toBe('k');
  });
});

describe('resolveAzureEmbeddingsForModel', () => {
  it('builds embeddings URL for a configured model', () => {
    const cfg = {
      modelGroupMap: { 'text-embedding-3': { group: 'g1' } },
      groupMap: {
        g1: {
          instanceName: 'my-instance',
          apiKey: 'ek',
          version: '2025-01-01-preview',
          models: {
            'text-embedding-3': {
              deploymentName: 'text-embedding-3',
              version: '2025-01-01-preview',
            },
          },
        },
      },
    } as unknown as TAzureConfig;

    const { url, headers } = resolveAzureEmbeddingsForModel('text-embedding-3', cfg);
    expect(url).toContain('/openai/deployments/text-embedding-3/embeddings');
    expect(url).toContain('api-version=2025-01-01-preview');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['api-key']).toBe('ek');
  });
});

describe('resolveAzureChatCompletionsForModel', () => {
  it('builds chat completions URL for a configured model', () => {
    const cfg = {
      modelGroupMap: {
        'gpt-5.4': { group: 'g1' },
      },
      groupMap: {
        g1: {
          instanceName: 'my-instance',
          apiKey: 'test-key',
          version: '2025-01-01-preview',
          models: {
            'gpt-5.4': {
              deploymentName: 'gpt-5.4',
              version: '2025-01-01-preview',
            },
          },
        },
      },
    } as unknown as TAzureConfig;

    const { url, headers } = resolveAzureChatCompletionsForModel('gpt-5.4', cfg);
    expect(url).toContain('my-instance');
    expect(url).toContain('/openai/deployments/gpt-5.4/chat/completions');
    expect(url).toContain('api-version=2025-01-01-preview');
    expect(headers['api-key']).toBe('test-key');
  });
});
