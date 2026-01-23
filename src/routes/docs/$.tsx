import browserCollections from 'fumadocs-mdx:collections/browser';
import { createFileRoute, notFound } from '@tanstack/react-router';
import { createServerFn } from '@tanstack/react-start';
import type { Root } from 'fumadocs-core/page-tree';
import { useFumadocsLoader } from 'fumadocs-core/source/client';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
} from 'fumadocs-ui/layouts/docs/page';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Suspense } from 'react';
import { baseOptions } from '@/lib/layout.shared';
import { source } from '@/lib/source';
import * as m from '@/paraglide/messages';
import { getLocale } from '@/paraglide/runtime';

export const Route = createFileRoute('/docs/$')({
  component: Page,
  loader: async ({ params }) => {
    const data = await loader({
      data: {
        slugs: params._splat?.split('/') ?? [],
        lang: getLocale(),
      },
    });
    await clientLoader.preload(data.path);
    return data;
  },
});

const loader = createServerFn({
  method: 'GET',
})
  .inputValidator((params: { slugs: string[]; lang?: string }) => params)
  .handler(async ({ data: { slugs, lang } }) => {
    // Some locales may have partial docs coverage. Prefer requested locale, but fall back to default.
    const localizedPage = source.getPage(slugs, lang);
    const page = localizedPage ?? source.getPage(slugs);
    if (!page) throw notFound();
    return {
      tree: source.getPageTree(localizedPage ? lang : undefined) as object,
      path: page.path,
    };
  });

const clientLoader = browserCollections.docs.createClientLoader({
  component(
    { toc, frontmatter, default: MDX },
    // you can define props for the component
    props: {
      className?: string;
    },
  ) {
    return (
      <DocsPage toc={toc} {...props}>
        <DocsTitle>{frontmatter.title}</DocsTitle>
        <DocsDescription>{frontmatter.description}</DocsDescription>
        <DocsBody>
          <MDX
            components={{
              ...defaultMdxComponents,
            }}
          />
        </DocsBody>
      </DocsPage>
    );
  },
});

function Page() {
  const data = useFumadocsLoader(Route.useLoaderData());
  return (
    <DocsLayout {...baseOptions()} tree={data.tree as Root}>
      <Suspense
        fallback={
          <div className="px-6 py-8" aria-busy="true" aria-live="polite">
            <div className="text-sm text-muted-foreground">
              {m.docs_loading()}
            </div>
            <div className="mt-4 space-y-3">
              <div className="h-8 w-64 rounded bg-muted/60 animate-pulse" />
              <div className="h-4 w-96 max-w-full rounded bg-muted/60 animate-pulse" />
              <div className="h-4 w-80 max-w-full rounded bg-muted/60 animate-pulse" />
              <div className="h-4 w-md max-w-full rounded bg-muted/60 animate-pulse" />
            </div>
          </div>
        }
      >
        {clientLoader.useContent(data.path, {
          className: '',
        })}
      </Suspense>
    </DocsLayout>
  );
}
