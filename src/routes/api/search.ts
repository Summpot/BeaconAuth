import { createFileRoute } from '@tanstack/react-router';
import { createFromSource } from 'fumadocs-core/search/server';
import { source } from '@/lib/source';

const server = createFromSource(source, {
  // https://docs.orama.com/docs/orama-js/supported-languages
  language: 'english',
  // CJK locales are not part of Orama's supported languages; fall back to
  // English tokenization so the search index builds without throwing.
  localeMap: {
    'zh-Hans': { language: 'english' },
    'zh-Hant': { language: 'english' },
    ko: { language: 'english' },
    ja: { language: 'english' },
  },
});
export const Route = createFileRoute('/api/search')({
  server: {
    handlers: {
      GET: async ({ request }) => server.GET(request),
    },
  },
});
