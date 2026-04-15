import type { TAzureConfig } from 'librechat-data-provider';
import { resolveAzureChatCompletionsForModel } from './resolveAzureChatCompletions';

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
