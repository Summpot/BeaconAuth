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

function DocsLoadingFallback() {
  return (
    <div
      className="relative overflow-hidden px-6 py-10"
      aria-busy="true"
      aria-live="polite"
    >
      {/* Subtle background glow matching the app's Scandi palette */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-10 right-[8%] h-64 w-64 rounded-full bg-primary/[0.03] blur-3xl dark:bg-primary/[0.05]" />
        <div className="absolute top-16 left-[-6%] h-72 w-72 rounded-full bg-accent/30 blur-3xl dark:bg-accent/10" />
      </div>
      <div className="relative">
        {/* Title row with inline shimmer rail */}
        <div className="flex items-center gap-3">
          <span className="inline-flex size-7 items-center justify-center rounded-lg border border-border/60 bg-card/80">
            <span className="size-2.5 rounded-full bg-primary/40 animate-pulse" />
          </span>
          <span className="text-sm font-medium tracking-tight text-muted-foreground">
            {m.docs_loading()}
          </span>
        </div>
        <div className="mt-3 h-1 w-20 overflow-hidden rounded-full bg-border/70">
          <div className="h-full w-1/2 rounded-full bg-gradient-to-r from-transparent via-primary/60 to-transparent animate-pulse" />
        </div>
        {/* Content skeleton — staggered, rounded, feels like DocsPage */}
        <div className="mt-8 space-y-4">
          <div className="h-7 w-[18rem] max-w-[72%] rounded-lg bg-muted/55 animate-pulse" />
          <div className="h-4 w-[26rem] max-w-full rounded-md bg-muted/40 animate-pulse [animation-delay:80ms]" />
          <div className="h-px w-full bg-border/50" />
          <div className="space-y-2.5 pt-1">
            <div className="h-3.5 w-full rounded-md bg-muted/45 animate-pulse [animation-delay:120ms]" />
            <div className="h-3.5 w-[92%] rounded-md bg-muted/35 animate-pulse [animation-delay:180ms]" />
            <div className="h-3.5 w-[88%] rounded-md bg-muted/35 animate-pulse [animation-delay:240ms]" />
            <div className="h-3.5 w-[78%] rounded-md bg-muted/30 animate-pulse [animation-delay:300ms]" />
          </div>
          <div className="flex gap-2 pt-2">
            <div className="h-8 w-24 rounded-lg bg-muted/35 animate-pulse [animation-delay:200ms]" />
            <div className="h-8 w-20 rounded-lg bg-muted/25 animate-pulse [animation-delay:260ms]" />
          </div>
        </div>
      </div>
    </div>
  );
}

function Page() {
  const data = useFumadocsLoader(Route.useLoaderData());
  return (
    <DocsLayout {...baseOptions()} tree={data.tree as Root}>
      <Suspense fallback={<DocsLoadingFallback />}>
        {clientLoader.useContent(data.path, {
          className: '',
        })}
      </Suspense>
    </DocsLayout>
  );
}
