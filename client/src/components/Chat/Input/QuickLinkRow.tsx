import { useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { GraduationCap, Lightbulb, ChevronDown, ChevronUp } from 'lucide-react';
import { TooltipAnchor } from '@librechat/client';
import { useLocalize } from '~/hooks';
import { useAgentsMapContext } from '~/Providers';
import useSelectAgent from '~/hooks/Agents/useSelectAgent';
import { cn } from '~/utils';

const ACADEMY_URL = 'https://academy.qima.com/catalog/keyword/gpt';

const FAQ_AGENT_NAME = 'QIMAgpt FAQ';

const STORAGE_KEY = 'quick-links-collapsed';
/** Bump this when links change so returning users see the updated row expanded. */
const CURRENT_VERSION = 2;

function readCollapsed(): boolean {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) {
      return false;
    }
    const parsed: { collapsed: boolean; version: number } = JSON.parse(raw);
    if (parsed.version !== CURRENT_VERSION) {
      localStorage.removeItem(STORAGE_KEY);
      return false;
    }
    return parsed.collapsed;
  } catch {
    return false;
  }
}

function writeCollapsed(collapsed: boolean): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ collapsed, version: CURRENT_VERSION }));
  } catch {
    /* noop */
  }
}

const linkClassName =
  'flex items-center gap-1.5 rounded-md border border-border-medium bg-transparent px-2.5 py-1.5 text-sm font-medium text-text-secondary transition-all duration-150 hover:bg-surface-tertiary';

export default function QuickLinkRow() {
  const localize = useLocalize();
  const navigate = useNavigate();
  const agentsMap = useAgentsMapContext();
  const { onSelect } = useSelectAgent();
  const [collapsed, setCollapsed] = useState(readCollapsed);

  const faqAgentId = useMemo(() => {
    if (!agentsMap) {
      return null;
    }
    for (const id in agentsMap) {
      if (agentsMap[id]?.name === FAQ_AGENT_NAME) {
        return id;
      }
    }
    return null;
  }, [agentsMap]);

  const handleFaqClick = useCallback(() => {
    if (!faqAgentId) {
      return;
    }
    navigate('/c/new');
    onSelect(faqAgentId);
  }, [faqAgentId, navigate, onSelect]);

  const toggle = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      writeCollapsed(next);
      return next;
    });
  }, []);

  return (
    <div className="mt-2 flex flex-col items-center gap-0.5 px-3">
      <div
        className={cn(
          'flex flex-wrap items-center justify-center gap-1.5 overflow-hidden transition-all duration-200',
          collapsed ? 'max-h-0 opacity-0' : 'max-h-24 opacity-100',
        )}
      >
        <TooltipAnchor
          description={localize('com_ui_quick_link_academy_tooltip')}
          render={
            <a
              href={ACADEMY_URL}
              target="_blank"
              rel="noopener noreferrer"
              tabIndex={collapsed ? -1 : 0}
              className={linkClassName}
              aria-label={localize('com_ui_quick_link_academy')}
            >
              <GraduationCap className="size-4" aria-hidden="true" />
              <span>{localize('com_ui_quick_link_academy')}</span>
            </a>
          }
        />
        {faqAgentId && (
          <TooltipAnchor
            description={localize('com_ui_quick_link_faq_tooltip')}
            render={
              <button
                type="button"
                onClick={handleFaqClick}
                tabIndex={collapsed ? -1 : 0}
                className={linkClassName}
                aria-label={localize('com_ui_quick_link_faq')}
              >
                <Lightbulb className="size-4" aria-hidden="true" />
                <span>{localize('com_ui_quick_link_faq')}</span>
              </button>
            }
          />
        )}
      </div>
      <TooltipAnchor
        description={
          collapsed
            ? localize('com_ui_quick_links_expand')
            : localize('com_ui_quick_links_collapse')
        }
        render={
          <button
            type="button"
            onClick={toggle}
            className="flex size-5 items-center justify-center rounded-full text-text-tertiary transition-colors duration-150 hover:bg-surface-tertiary hover:text-text-secondary"
            aria-label={
              collapsed
                ? localize('com_ui_quick_links_expand')
                : localize('com_ui_quick_links_collapse')
            }
          >
            {collapsed ? (
              <ChevronDown className="size-3.5" aria-hidden="true" />
            ) : (
              <ChevronUp className="size-3.5" aria-hidden="true" />
            )}
          </button>
        }
      />
    </div>
  );
}
