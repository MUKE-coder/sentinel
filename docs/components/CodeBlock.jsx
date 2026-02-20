'use client';

import { Highlight, themes } from 'prism-react-renderer';
import { useState } from 'react';
import { useTheme } from 'next-themes';
import { Copy, Check } from 'lucide-react';

export default function CodeBlock({ code, language = 'go', filename, showLineNumbers = true }) {
  const [copied, setCopied] = useState(false);
  const { resolvedTheme } = useTheme();

  const handleCopy = () => {
    navigator.clipboard.writeText(code.trim());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const theme = resolvedTheme === 'dark' ? themes.nightOwl : themes.nightOwlLight;

  return (
    <div className="group relative my-4 rounded-xl overflow-hidden border border-gray-200 dark:border-gray-800 bg-white dark:bg-[#011627]">
      {filename && (
        <div className="flex items-center justify-between px-4 py-2 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
          <span className="text-xs font-mono text-gray-500 dark:text-gray-400">{filename}</span>
          <span className="text-xs text-gray-400 dark:text-gray-500 uppercase">{language}</span>
        </div>
      )}
      <div className="relative">
        <button
          onClick={handleCopy}
          className="absolute right-3 top-3 z-10 p-1.5 rounded-md bg-gray-100/80 dark:bg-gray-800/80 hover:bg-gray-200 dark:hover:bg-gray-700 opacity-0 group-hover:opacity-100 transition-opacity"
          aria-label="Copy code"
        >
          {copied ? (
            <Check size={14} className="text-green-500" />
          ) : (
            <Copy size={14} className="text-gray-500 dark:text-gray-400" />
          )}
        </button>
        <Highlight theme={theme} code={code.trim()} language={language}>
          {({ tokens, getLineProps, getTokenProps }) => (
            <pre className="overflow-x-auto p-4 text-[13px] leading-relaxed">
              {tokens.map((line, i) => (
                <div key={i} {...getLineProps({ line })}>
                  {showLineNumbers && (
                    <span className="inline-block w-8 text-right mr-4 text-gray-400 dark:text-gray-600 select-none text-xs">
                      {i + 1}
                    </span>
                  )}
                  {line.map((token, key) => (
                    <span key={key} {...getTokenProps({ token })} />
                  ))}
                </div>
              ))}
            </pre>
          )}
        </Highlight>
      </div>
    </div>
  );
}
