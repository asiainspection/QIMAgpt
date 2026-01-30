import React, { useState, useCallback } from 'react';
import { useWatch } from 'react-hook-form';
import type { Control } from 'react-hook-form';
import { Search } from 'lucide-react';
import { OGDialog, OGDialogContent, OGDialogTitle, OGDialogClose, Spinner, useToastContext, TooltipAnchor } from '@librechat/client';
import { isAgentsEndpoint } from 'librechat-data-provider';
import { dataService } from 'librechat-data-provider';
import Markdown from '~/components/Chat/Messages/Content/Markdown';
import { useLocalize } from '~/hooks';
import { cn } from '~/utils';

type DeepResearchButtonProps = {
  control: Control<{ text: string }>;
  disabled: boolean;
  endpoint: string | undefined;
  isRTL?: boolean;
};

export default function DeepResearchButton({
  control,
  disabled,
  endpoint,
  isRTL = false,
}: DeepResearchButtonProps) {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  const text = useWatch({ control, name: 'text', defaultValue: '' });
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleClick = useCallback(async () => {
    const instructions = (text ?? '').trim();
    if (!instructions) {
      showToast(localize('com_ui_deep_research_enter_question') || 'Please enter a research question');
      return;
    }
    setShowModal(true);
    setLoading(true);
    setError(null);
    setReport('');
    try {
      const res = await dataService.runExaResearch(instructions);
      setReport(res.report ?? '');
      setError(res.status === 'failed' ? res.report : null);
    } catch (err: unknown) {
      const ax = err && typeof err === 'object' && 'response' in err ? (err as { response?: { data?: { message?: string } } }).response : null;
      const message = ax?.data?.message ?? (err && typeof err === 'object' && 'message' in err ? String((err as { message: string }).message) : 'Deep Research failed');
      setError(message);
      showToast(message);
    } finally {
      setLoading(false);
    }
  }, [text, showToast, localize]);

  if (!endpoint || !isAgentsEndpoint(endpoint)) {
    return null;
  }

  const buttonDisabled = disabled || !(text ?? '').trim();

  return (
    <>
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
            <Search className="icon-md" />
          </button>
        }
      />
      <OGDialog open={showModal} onOpenChange={setShowModal}>
        <OGDialogContent className="flex max-h-[85vh] max-w-full flex-col overflow-hidden rounded-lg bg-surface-primary p-0 md:max-w-[700px]">
          <div className="flex shrink-0 items-center justify-between border-b border-border-light px-3 py-2">
            <OGDialogTitle className="text-base font-medium">
              {localize('com_ui_deep_research') || 'Deep Research'}
            </OGDialogTitle>
            <OGDialogClose className="rounded-md p-1 hover:bg-surface-active-alt" />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
            {loading && (
              <div className="flex items-center justify-center gap-2 py-8">
                <Spinner className="icon-md" />
                <span className="text-sm text-text-secondary">
                  {localize('com_ui_deep_research_running') || 'Researching…'}
                </span>
              </div>
            )}
            {!loading && error && (
              <p className="text-sm text-red-500">{error}</p>
            )}
            {!loading && !error && report && (
              <div className="markdown prose message-content dark:prose-invert w-full break-words text-sm">
                <Markdown content={report} isLatestMessage={false} />
              </div>
            )}
          </div>
        </OGDialogContent>
      </OGDialog>
    </>
  );
}
