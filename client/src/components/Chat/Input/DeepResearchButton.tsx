import React, { useState, useCallback } from 'react';
import { useWatch } from 'react-hook-form';
import type { Control } from 'react-hook-form';
import { v4 } from 'uuid';
import { Search } from 'lucide-react';
import { Spinner, useToastContext, TooltipAnchor } from '@librechat/client';
import { Constants, isAgentsEndpoint } from 'librechat-data-provider';
import type { TMessage } from 'librechat-data-provider';
import { dataService } from 'librechat-data-provider';
import { useChatContext } from '~/Providers';
import { useLocalize } from '~/hooks';
import { cn } from '~/utils';

type DeepResearchButtonProps = {
  control: Control<{ text: string }>;
  disabled: boolean;
  endpoint: string | undefined;
};

export default function DeepResearchButton({
  control,
  disabled,
  endpoint,
}: DeepResearchButtonProps) {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  const text = useWatch({ control, name: 'text', defaultValue: '' });
  const [loading, setLoading] = useState(false);
  const { conversation, getMessages, setMessages, latestMessage } = useChatContext();
  const service = dataService as unknown as {
    runExaResearch: (instructions: string) => Promise<{ report: string; status: string }>;
    createMessage: (conversationId: string, message: Record<string, unknown>) => Promise<unknown>;
  };

  const handleClick = useCallback(async () => {
    const instructions = (text ?? '').trim();
    if (!instructions) {
      showToast({
        message:
          localize('com_ui_deep_research_enter_question') || 'Please enter a research question',
        status: 'warning',
      });
      return;
    }
    setLoading(true);
    try {
      const convoId = conversation?.conversationId ?? Constants.NEW_CONVO;
      if (!convoId || convoId === Constants.NEW_CONVO) {
        showToast({
          message: localize('com_ui_deep_research_start_convo') || 'Start a conversation first',
          status: 'warning',
        });
        return;
      }
      const res = await service.runExaResearch(instructions);
      const report = res.report ?? '';
      const parentMessageId = latestMessage?.messageId ?? Constants.NO_PARENT;
      const threadId = latestMessage?.thread_id;
      const endpointValue = conversation?.endpoint ?? conversation?.endpointType ?? '';

      const userMessageId = v4();
      const assistantMessageId = v4();
      const now = new Date().toLocaleString('sv').replace(' ', 'T');

      const userMessage = {
        text: instructions,
        sender: 'User',
        clientTimestamp: now,
        isCreatedByUser: true,
        parentMessageId,
        conversationId: convoId,
        messageId: userMessageId,
        thread_id: threadId,
        error: false,
      };

      const assistantMessage = {
        text: report,
        sender: conversation?.agent_id ?? conversation?.model ?? 'Deep Research',
        endpoint: endpointValue,
        parentMessageId: userMessageId,
        conversationId: convoId,
        messageId: assistantMessageId,
        thread_id: threadId,
        isCreatedByUser: false,
        error: false,
      };

      const savedUser = await service.createMessage(convoId, userMessage);
      const savedAssistant = await service.createMessage(convoId, assistantMessage);
      const savedUserMessage = (savedUser as TMessage) ?? (userMessage as TMessage);
      const savedAssistantMessage = (savedAssistant as TMessage) ?? (assistantMessage as TMessage);
      const current = getMessages() ?? [];
      setMessages([...current, savedUserMessage, savedAssistantMessage]);
    } catch (err: unknown) {
      const ax = err && typeof err === 'object' && 'response' in err ? (err as { response?: { data?: { message?: string } } }).response : null;
      const message = ax?.data?.message ?? (err && typeof err === 'object' && 'message' in err ? String((err as { message: string }).message) : 'Deep Research failed');
      showToast({ message, status: 'error' });
    } finally {
      setLoading(false);
    }
  }, [text, showToast, localize, conversation, latestMessage, getMessages, setMessages]);

  if (!endpoint || !isAgentsEndpoint(endpoint)) {
    return null;
  }

  const buttonDisabled = disabled || loading || !(text ?? '').trim();

  return (
    <TooltipAnchor
      description={localize('com_ui_deep_research') || 'Deep Research'}
      render={
        <button
          type="button"
          aria-label={localize('com_ui_deep_research') || 'Deep Research'}
          disabled={buttonDisabled}
          onClick={handleClick}
          className={cn(
            'rounded-full p-1.5 text-text-primary outline-offset-4 transition-all duration-200',
            'hover:bg-surface-active-alt disabled:cursor-not-allowed disabled:text-text-secondary disabled:opacity-10',
          )}
        >
          {loading ? <Spinner className="icon-md" /> : <Search className="icon-md" />}
        </button>
      }
    />
  );
}
