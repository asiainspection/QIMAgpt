import ReactMarkdown from 'react-markdown';
import type { TStartupConfig } from 'librechat-data-provider';
import { useGetStartupConfig } from '~/data-provider';

type FooterStartupConfig = Pick<Partial<TStartupConfig>, 'customFooter'>;

type FooterQimaProps = {
  className?: string;
  startupConfig?: FooterStartupConfig | null;
};

const DEFAULT_FOOTER = 'QIMAgpt. Get things done, faster, better.';

export default function FooterQima({ className, startupConfig }: FooterQimaProps) {
  const shouldFetchConfig = startupConfig === undefined;
  const { data: fetchedConfig } = useGetStartupConfig({ enabled: shouldFetchConfig });
  const config = shouldFetchConfig ? fetchedConfig : startupConfig;

  const footerText =
    typeof config?.customFooter === 'string' && config.customFooter.length > 0
      ? config.customFooter
      : DEFAULT_FOOTER;

  return (
    <div
      className={
        className ??
        'hidden px-3 pb-1 pt-2 text-center text-xs text-black/50 dark:text-white/50 md:block md:px-4 md:pb-4 md:pt-3'
      }
      role="contentinfo"
    >
      <ReactMarkdown
        components={{
          a: ({ node: _n, href, children, ...otherProps }) => (
            <a className="underline" href={href} rel="noreferrer" {...otherProps}>
              {children}
            </a>
          ),
          p: ({ node: _n, ...props }) => <span {...props} />,
        }}
      >
        {footerText}
      </ReactMarkdown>
    </div>
  );
}
