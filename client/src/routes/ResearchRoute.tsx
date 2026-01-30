import React, { useState, useCallback } from 'react';
import { Spinner, useToastContext } from '@librechat/client';
import { dataService } from 'librechat-data-provider';
import { useDocumentTitle, useLocalize } from '~/hooks';
import Markdown from '~/components/Chat/Messages/Content/Markdown';
import { cn } from '~/utils';

function getReportText(report: unknown): string {
  if (typeof report === 'string') return report;
  if (report && typeof report === 'object' && 'content' in report && typeof (report as { content: unknown }).content === 'string') {
    return (report as { content: string }).content;
  }
  return '';
}

export default function ResearchRoute() {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  useDocumentTitle(`${localize('com_ui_deep_research') || 'Deep Research'} | LibreChat`);

  const [instructions, setInstructions] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = instructions.trim();
      if (!trimmed) {
        showToast({ message: localize('com_ui_deep_research_enter_question') || 'Please enter a research question', status: 'warning' });
        return;
      }
      setLoading(true);
      setError(null);
      setReport('');
      try {
        const res = await dataService.runExaResearch(trimmed);
        const text = getReportText(res.report);
        setReport(text);
        if (res.status === 'failed') {
          setError(text || 'Research failed');
        }
      } catch (err: unknown) {
        const ax = err && typeof err === 'object' && 'response' in err ? (err as { response?: { data?: { message?: string } } }).response : null;
        const message = ax?.data?.message ?? (err && typeof err === 'object' && 'message' in err ? String((err as { message: string }).message) : 'Deep Research failed');
        setError(message);
        showToast({ message, status: 'error' });
      } finally {
        setLoading(false);
      }
    },
    [instructions, showToast, localize],
  );

  return (
    <div className="flex h-full w-full flex-col items-center overflow-y-auto bg-surface-primary">
      <div className="flex w-full max-w-3xl flex-col gap-4 p-4 md:p-6">
        <h1 className="text-xl font-semibold text-text-primary">
          {localize('com_ui_deep_research') || 'Deep Research'}
        </h1>
        <p className="text-sm text-text-secondary">
          {localize('com_ui_deep_research_description') || 'Enter a research question. Exa will search the web and synthesize a report with citations.'}
        </p>
        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <textarea
            value={instructions}
            onChange={(e) => setInstructions(e.target.value)}
            placeholder={localize('com_ui_deep_research_enter_question') || 'e.g. Compare the top Gold ETFs in 2025'}
            className="min-h-[100px] w-full resize-y rounded-lg border border-border-medium bg-surface-secondary px-3 py-2 text-text-primary placeholder:text-text-secondary focus:border-border-active focus:outline-none"
            maxLength={4096}
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !instructions.trim()}
            className={cn(
              'flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-text-primary px-4 text-sm font-medium text-surface-primary',
              'hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50',
            )}
          >
            {loading ? (
              <>
                <Spinner className="icon-sm" />
                <span>{localize('com_ui_deep_research_running') || 'Researching…'}</span>
              </>
            ) : (
              localize('com_ui_deep_research_start') || 'Start Research'
            )}
          </button>
        </form>
        {error && <p className="text-sm text-red-500">{error}</p>}
        {report && !error && (
          <div className="mt-4 rounded-lg border border-border-light bg-surface-primary-contrast p-4">
            <div className="markdown prose message-content dark:prose-invert w-full break-words text-sm">
              <Markdown content={report} isLatestMessage={false} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
