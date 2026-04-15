import type { TAzureConfig } from 'librechat-data-provider';
import {
  effectivePassthroughApiVersion,
  resolveAzureChatCompletionsForModel,
  resolveAzureEmbeddingsForModel,
  resolveAzureOpenAIGetResponseForModel,
  resolveAzureOpenAIResponsesForModel,
} from './resolveAzureChatCompletions';

describe('effectivePassthroughApiVersion', () => {
  const keys = [
    'AZURE_OPENAI_PASSTHROUGH_API_VERSION',
    'AZURE_OPENAI_RESPONSES_API_VERSION',
    'AZURE_OPENAI_CHAT_API_VERSION',
  ] as const;
  const snapshot: Partial<Record<(typeof keys)[number], string | undefined>> = {};

  beforeEach(() => {
    for (const k of keys) {
      snapshot[k] = process.env[k];
    }
  });

  afterEach(() => {
    for (const k of keys) {
      const v = snapshot[k];
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
  });

  it('prefers AZURE_OPENAI_PASSTHROUGH_API_VERSION over mapped value', () => {
    process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION = '2025-03-01-preview';
    delete process.env.AZURE_OPENAI_RESPONSES_API_VERSION;
    delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
    expect(effectivePassthroughApiVersion('2024-02-15-preview', 'responses')).toBe(
      '2025-03-01-preview',
    );
    expect(effectivePassthroughApiVersion('2024-02-15-preview', 'chatOrEmbeddings')).toBe(
      '2025-03-01-preview',
    );
  });

  it('uses AZURE_OPENAI_RESPONSES_API_VERSION for responses kind', () => {
    delete process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION;
    process.env.AZURE_OPENAI_RESPONSES_API_VERSION = '2025-01-01-preview';
    delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
    expect(effectivePassthroughApiVersion('2024-02-15-preview', 'responses')).toBe(
      '2025-01-01-preview',
    );
    expect(effectivePassthroughApiVersion('2024-02-15-preview', 'chatOrEmbeddings')).toBe(
      '2024-02-15-preview',
    );
  });

  it('for responses without env uses fallback when mapped version predates Responses route support', () => {
    delete process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION;
    delete process.env.AZURE_OPENAI_RESPONSES_API_VERSION;
    delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
    expect(effectivePassthroughApiVersion('2025-01-01-preview', 'responses')).toBe(
      '2025-04-01-preview',
    );
  });

  it('for responses without env keeps mapped version when already new enough', () => {
    delete process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION;
    delete process.env.AZURE_OPENAI_RESPONSES_API_VERSION;
    delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
    expect(effectivePassthroughApiVersion('2025-03-01-preview', 'responses')).toBe(
      '2025-03-01-preview',
    );
  });
});

describe('resolveAzureOpenAIResponsesForModel', () => {
  const foundryEnvKeys = [
    'AZURE_OPENAI_PASSTHROUGH_API_VERSION',
    'AZURE_OPENAI_RESPONSES_API_VERSION',
    'AZURE_OPENAI_V1_API_VERSION',
    'AZURE_OPENAI_CHAT_API_VERSION',
  ] as const;
  const foundryEnvSnapshot: Partial<Record<(typeof foundryEnvKeys)[number], string | undefined>> =
    {};

  describe('Foundry serverless base …/openai/v1', () => {
    const foundryCfg = {
      modelGroupMap: { 'gpt-5.4': { group: 'foundry' } },
      groupMap: {
        foundry: {
          apiKey: 'k',
          baseURL: 'https://qimagpt-eastus2.openai.azure.com/openai/v1',
          serverless: true,
          version: '2025-01-01-preview',
          models: { 'gpt-5.4': true },
        },
      },
    } as unknown as TAzureConfig;

    beforeEach(() => {
      for (const k of foundryEnvKeys) {
        foundryEnvSnapshot[k] = process.env[k];
      }
    });

    afterEach(() => {
      for (const k of foundryEnvKeys) {
        const v = foundryEnvSnapshot[k];
        if (v === undefined) {
          delete process.env[k];
        } else {
          process.env[k] = v;
        }
      }
    });

    it('resolves to …/openai/v1/responses without duplicate path; omits api-version by default', () => {
      for (const k of foundryEnvKeys) {
        delete process.env[k];
      }
      const { url } = resolveAzureOpenAIResponsesForModel('gpt-5.4', foundryCfg);
      expect(url).toBe('https://qimagpt-eastus2.openai.azure.com/openai/v1/responses');
      expect(url.includes('/openai/v1/openai/')).toBe(false);
    });

    it('appends api-version when AZURE_OPENAI_RESPONSES_API_VERSION is set', () => {
      delete process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION;
      process.env.AZURE_OPENAI_RESPONSES_API_VERSION = '2025-03-01-preview';
      delete process.env.AZURE_OPENAI_V1_API_VERSION;
      delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
      const { url } = resolveAzureOpenAIResponsesForModel('gpt-5.4', foundryCfg);
      expect(url).toBe(
        'https://qimagpt-eastus2.openai.azure.com/openai/v1/responses?api-version=2025-03-01-preview',
      );
    });

    it('prefers AZURE_OPENAI_PASSTHROUGH_API_VERSION over AZURE_OPENAI_RESPONSES_API_VERSION', () => {
      process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION = '2025-04-01-preview';
      process.env.AZURE_OPENAI_RESPONSES_API_VERSION = '2025-03-01-preview';
      delete process.env.AZURE_OPENAI_V1_API_VERSION;
      delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
      const { url } = resolveAzureOpenAIResponsesForModel('gpt-5.4', foundryCfg);
      expect(url).toContain('api-version=2025-04-01-preview');
    });

    it('uses AZURE_OPENAI_V1_API_VERSION when other overrides are unset', () => {
      delete process.env.AZURE_OPENAI_PASSTHROUGH_API_VERSION;
      delete process.env.AZURE_OPENAI_RESPONSES_API_VERSION;
      process.env.AZURE_OPENAI_V1_API_VERSION = 'preview';
      delete process.env.AZURE_OPENAI_CHAT_API_VERSION;
      const { url } = resolveAzureOpenAIResponsesForModel('gpt-5.4', foundryCfg);
      expect(url).toBe('https://qimagpt-eastus2.openai.azure.com/openai/v1/responses?api-version=preview');
    });

    it('GET response omits api-version by default on Foundry v1 base', () => {
      for (const k of foundryEnvKeys) {
        delete process.env[k];
      }
      const { url } = resolveAzureOpenAIGetResponseForModel('gpt-5.4', 'resp_abc', foundryCfg);
      expect(url).toBe('https://qimagpt-eastus2.openai.azure.com/openai/v1/responses/resp_abc');
    });
  });

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
    expect(url).toContain('api-version=2025-04-01-preview');
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
    expect(url).toContain('api-version=2025-04-01-preview');
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
