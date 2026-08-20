import {
  createRouter,
  parseSearchWith,
  stringifySearchWith,
} from '@tanstack/react-router';
import { deLocalizeUrl, localizeUrl } from './paraglide/runtime.js';
import { routeTree } from './routeTree.gen';

/**
 * TanStack Router's default `parseSearch` coerces query-string values into
 * booleans/numbers via `JSON.parse` (e.g. `1` becomes the number `1`, `true`
 * becomes the boolean `true`). The OIDC/OAuth search-param schemas expect raw
 * strings, so we keep every value a string.
 */
const parseSearch = parseSearchWith((value) => value);
// The stringify parser must throw for plain strings so they stay unencoded;
// only structured values (arrays/objects) get JSON-stringified by the wrapper.
const stringifySearch = stringifySearchWith(JSON.stringify, () => {
  throw new Error('keep plain string values unencoded');
});

export function getRouter() {
  const router = createRouter({
    routeTree,
    scrollRestoration: true,
    parseSearch,
    stringifySearch,
    rewrite: {
      input: ({ url }) => deLocalizeUrl(url),
      output: ({ url }) => localizeUrl(url),
    },
  });

  return router;
}
