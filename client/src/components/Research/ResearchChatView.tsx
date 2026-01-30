import React, { useCallback, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Spinner } from '@librechat/client';
import type { TMessage } from 'librechat-data-provider';
import { QueryKeys, dataService } from 'librechat-data-provider';
import { useDocumentTitle, useLocalize } from '~/hooks';
import Markdown from '~/components/Chat/Messages/Content/Markdown';
import { cn } from '~/utils';

function ResearchMessageRow({ message }: { message: TMessage }) {
  const isUser = message.isCreatedByUser === true;
  return (
    <div
      className={cn(
        'm-auto flex w-full max-w-3xl gap-3 px-3 py-4 md:gap-4 md:px-4',
        isUser ? 'justify-end' : 'justify-start',
      )}
    >
      <div
        className={cn(
          'flex max-w-[85%] flex-col gap-1 rounded-2xl px-3 py-2 md:max-w-[80%]',
          isUser
            ? 'bg-surface-active-alt text-text-primary'
            : 'bg-surface-primary-contrast text-text-primary',
        )}
      >
        <div className="markdown prose message-content dark:prose-invert w-full break-words text-sm">
          <Markdown content={message.text ?? ''} isLatestMessage={false} />
        </div>
      </div>
    </div>
  );
}

function ResearchInProgressRow() {
  const localize = useLocalize();
  return (
    <div className="m-auto flex w-full max-w-3xl gap-3 px-3 py-4 md:gap-4 md:px-4">
      <div className="flex items-center gap-2 rounded-2xl bg-surface-primary-contrast px-3 py-2 text-text-secondary">
        <Spinner className="icon-sm" />
        <span className="text-sm">{localize('com_ui_deep_research_running') || 'Researching…'}</span>
      </div>
    </div>
  );
}

export default function ResearchChatView() {
  const { conversationId } = useParams<{ conversationId?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const localize = useLocalize();
  const [input, setInput] = useState('');
  const [isResearching, setIsResearching] = useState(false);

  useDocumentTitle(`${localize('com_ui_deep_research') || 'Deep Research'} | LibreChat`);

  const isNew = !conversationId || conversationId === 'new';
  const convoId = isNew ? undefined : conversationId;

  const { data: messages = [], isLoading } = useQuery({
    queryKey: [QueryKeys.messages, convoId ?? 'research'],
    queryFn: () => (convoId ? dataService.getResearchMessages(convoId) : Promise.resolve([])),
    enabled: !!convoId,
  });

  const sortedMessages = React.useMemo(() => {
    if (!messages.length) return [];
    return [...messages].sort(
      (a, b) =>
        new Date(a.createdAt ?? 0).getTime() - new Date(b.createdAt ?? 0).getTime(),
    );
  }, [messages]);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const text = input.trim();
      if (!text || isResearching) return;
      setIsResearching(true);
      try {
        let targetConvoId = convoId;
        if (!targetConvoId) {
          const created = await dataService.createResearchConversation();
          targetConvoId = created.conversationId;
          navigate(`/research/c/${targetConvoId}`, { replace: true });
        }
        if (!targetConvoId) {
          setIsResearching(false);
          return;
        }
        await dataService.submitResearchMessage(targetConvoId, text);
        setInput('');
        await queryClient.invalidateQueries({ queryKey: [QueryKeys.messages, targetConvoId] });
      } catch (err) {
        console.error('[ResearchChatView] submit error', err);
      } finally {
        setIsResearching(false);
      }
    },
    [input, isResearching, convoId, navigate, queryClient],
  );

  const isEmpty = !convoId || (sortedMessages.length === 0 && !isResearching);
  const showLanding = isEmpty && isNew;

  return (
    <div className="flex h-full w-full flex-col bg-surface-primary">
      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto">
          {showLanding && (
            <div className="flex flex-col items-center justify-center gap-2 px-4 py-8">
              <h1 className="text-xl font-semibold text-text-primary">
                {localize('com_ui_deep_research') || 'Deep Research'}
              </h1>
              <p className="max-w-md text-center text-sm text-text-secondary">
                {localize('com_ui_deep_research_description') ||
                  'Enter a research question. Exa will search the web and synthesize a report with citations.'}
              </p>
            </div>
          )}
          {isLoading && convoId && (
            <div className="flex h-32 items-center justify-center">
              <Spinner className="text-text-primary" />
            </div>
          )}
          {!isLoading && convoId && (
            <>
              {sortedMessages.map((msg) => (
                <ResearchMessageRow key={msg.messageId} message={msg} />
              ))}
              {isResearching && <ResearchInProgressRow />}
            </>
          )}
          <div id="research-messages-end" className="h-0 flex-shrink-0" />
        </div>
        <div className="w-full border-t border-border-medium bg-surface-primary p-3">
          <form onSubmit={handleSubmit} className="m-auto flex max-w-3xl gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                localize('com_ui_deep_research_enter_question') ||
                'e.g. Compare the top Gold ETFs in 2025'
              }
              className="flex-1 rounded-lg border border-border-medium bg-surface-secondary px-3 py-2 text-text-primary placeholder:text-text-secondary focus:border-border-active focus:outline-none"
              maxLength={4096}
              disabled={isResearching}
            />
            <button
              type="submit"
              disabled={isResearching || !input.trim()}
              className={cn(
                'rounded-lg px-4 py-2 text-sm font-medium text-surface-primary',
                'bg-text-primary hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50',
              )}
            >
              {isResearching
                ? localize('com_ui_deep_research_running') || 'Researching…'
                : localize('com_ui_deep_research_start') || 'Start Research'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
