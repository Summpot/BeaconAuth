import browserCollections from 'fumadocs-mdx:collections/browser';
import { createFileRoute, notFound } from '@tanstack/react-router';
import { createServerFn } from '@tanstack/react-start';
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
import { getLocale } from '@/paraglide/runtime';
import type { Root } from 'fumadocs-core/page-tree';

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
    const page = source.getPage(slugs, lang);
    if (!page) throw notFound();
    return {
      tree: source.getPageTree(lang) as object,
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
  const lang = getLocale();
  const data = useFumadocsLoader(Route.useLoaderData());
  return (
    <DocsLayout {...baseOptions(lang)} tree={data.tree as Root}>
      <Suspense>
        {clientLoader.useContent(data.path, {
          className: '',
        })}
      </Suspense>
    </DocsLayout>
  );
}
