import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Gamepad2, Github, KeyRound, Shield } from 'lucide-react';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys, type UserInfo } from '../utils/api';

const FEATURES = [
  {
    icon: KeyRound,
    title: m.card_multi_auth_title,
    description: m.card_multi_auth_desc,
    container: 'bg-primary-container text-on-primary-container',
  },
  {
    icon: Shield,
    title: m.card_enterprise_security_title,
    description: m.card_enterprise_security_desc,
    container: 'bg-secondary-container text-on-secondary-container',
  },
  {
    icon: Gamepad2,
    title: m.card_seamless_integration_title,
    description: m.card_seamless_integration_desc,
    container: 'bg-tertiary-container text-on-tertiary-container',
  },
] as const;

export function HomePage() {
  const { data: user } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: async (): Promise<UserInfo | null> => {
      try {
        return await apiClient<UserInfo>('/api/v1/user/me', {
          requiresAuth: false,
        });
      } catch {
        return null;
      }
    },
  });

  return (
    <div className="min-h-full bg-surface text-on-surface">
      {/* Hero */}
      <section className="relative overflow-hidden px-6 pt-16 pb-20 md:pt-24 md:pb-28">
        <div className="relative z-10 mx-auto max-w-5xl text-center">
          {/* M3 suggestion chip */}
          <div className="mb-10 inline-flex max-w-full items-center gap-2 rounded-sm bg-surface-container-high py-1.5 pr-4 pl-1.5">
            <span className="rounded-sm bg-primary px-2 py-1 text-label-sm text-on-primary uppercase">
              {m.home_badge_new()}
            </span>
            <span className="truncate text-label-lg text-on-surface-variant">
              {m.feature_passkeys_desc()}
            </span>
          </div>

          <h1 className="mb-6 text-balance text-headline-lg text-on-surface md:text-display-lg">
            {m.home_hero_title_1()}
            <span className="text-primary">{m.home_hero_title_2()}</span>
          </h1>

          <p className="mx-auto mb-12 max-w-3xl text-balance text-body-lg text-on-surface-variant md:text-title-lg">
            {m.home_hero_subtitle()}
          </p>

          <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
            {user ? (
              <>
                <Button size="lg" asChild>
                  <Link to="/profile">{m.button_view_profile()}</Link>
                </Button>
                <Button variant="outlined" size="lg" asChild>
                  <Link to="/settings">{m.button_manage_settings()}</Link>
                </Button>
              </>
            ) : (
              <>
                <Button size="lg" asChild>
                  <Link to="/login">{m.button_login_now()}</Link>
                </Button>
                <Button variant="tonal" size="lg" asChild>
                  <Link to="/register">{m.button_create_account()}</Link>
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Ambient tonal wash */}
        <div className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
          <div className="absolute top-[-14%] right-[-8%] size-[30rem] rounded-full bg-primary-container opacity-40 blur-3xl" />
          <div className="absolute bottom-[-16%] left-[-10%] size-[34rem] rounded-full bg-tertiary-container opacity-30 blur-3xl" />
        </div>
      </section>

      {/* Features */}
      <section className="bg-surface-container-low px-6 py-20 md:py-24">
        <div className="mx-auto max-w-7xl">
          <div className="mb-14 text-center">
            <h2 className="mb-4 text-headline-md text-on-surface md:text-headline-lg">
              {m.why_beaconauth_title()}
            </h2>
            <p className="mx-auto max-w-2xl text-balance text-body-lg text-on-surface-variant">
              {m.why_beaconauth_desc()}
            </p>
          </div>

          <div className="grid gap-6 md:grid-cols-3">
            {FEATURES.map((feature) => {
              const Icon = feature.icon;
              return (
                <Card
                  key={feature.title()}
                  variant="filled"
                  className="gap-0 py-0"
                >
                  <CardContent className="p-6">
                    <div
                      className={`mb-6 flex size-14 items-center justify-center rounded-md ${feature.container}`}
                    >
                      <Icon className="size-7" />
                    </div>
                    <h3 className="mb-2 text-title-lg text-on-surface">
                      {feature.title()}
                    </h3>
                    <p className="text-body-md text-on-surface-variant">
                      {feature.description()}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Call to action */}
      <section className="px-6 py-20 md:py-24">
        <div className="mx-auto max-w-5xl">
          <div className="rounded-xl bg-primary-container px-6 py-14 text-center text-on-primary-container md:px-16">
            <h2 className="mb-4 text-headline-md md:text-headline-lg">
              {m.cta_title()}
            </h2>
            <p className="mx-auto mb-10 max-w-2xl text-body-lg opacity-90">
              {m.cta_desc()}
            </p>
            <div className="flex flex-col justify-center gap-4 sm:flex-row">
              <Button size="lg" asChild>
                <Link to="/login">{m.button_try_demo()}</Link>
              </Button>
              <Button
                variant="outlined"
                size="lg"
                asChild
                className="border-on-primary-container/40 text-on-primary-container"
              >
                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Github />
                  {m.button_view_github()}
                </a>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-surface-container px-6 py-12">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-6 md:flex-row">
          <div className="flex items-center gap-3">
            <BeaconIcon className="size-8" />
            <div className="flex flex-col">
              <span className="text-title-md text-on-surface">
                {m.app_name()}
              </span>
              <span className="text-body-sm text-on-surface-variant">
                © 2026 Summpot
              </span>
            </div>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-2 text-label-lg text-on-surface-variant">
            <span>{m.footer_open_source()}</span>
            <span>{m.footer_license()}</span>
            <a
              href="https://github.com/Summpot/beacon_auth"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-xs transition-colors duration-200 ease-standard hover:text-primary"
            >
              {m.footer_contribute()}
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: HomePage,
});
