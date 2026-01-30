import React, { useCallback } from 'react';
import { Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { TooltipAnchor, Button } from '@librechat/client';
import { useLocalize } from '~/hooks';

interface DeepResearchNavButtonProps {
  isSmallScreen?: boolean;
  toggleNav: () => void;
}

export default function DeepResearchNavButton({
  isSmallScreen,
  toggleNav,
}: DeepResearchNavButtonProps) {
  const navigate = useNavigate();
  const localize = useLocalize();

  const handleClick = useCallback(() => {
    navigate('/research');
    if (isSmallScreen) {
      toggleNav();
    }
  }, [navigate, isSmallScreen, toggleNav]);

  return (
    <TooltipAnchor
      description={localize('com_ui_deep_research') || 'Deep Research'}
      render={
        <Button
          variant="outline"
          data-testid="nav-deep-research-button"
          aria-label={localize('com_ui_deep_research') || 'Deep Research'}
          className="rounded-full border-none bg-transparent p-2 hover:bg-surface-hover md:rounded-xl"
          onClick={handleClick}
        >
          <Search className="icon-md" />
        </Button>
      }
    />
  );
}
