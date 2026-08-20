import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Gamepad2, Github, KeyRound, Shield } from 'lucide-react';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys, type UserInfo } from '../utils/api';

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
    <div className="min-h-full bg-background text-foreground selection:bg-primary/15">
      {/* Hero Section */}
      <section className="relative pt-16 pb-20 md:pt-24 md:pb-24 overflow-hidden">
        <div className="container mx-auto px-6 relative z-10 text-center">
          <div className="inline-flex items-center justify-center gap-2 px-3 py-2 mb-8 rounded-full bg-card/60 border border-border/70">
            <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wide text-primary bg-primary/10 rounded-full">
              {m.home_badge_new()}
            </span>
            <span className="text-sm text-muted-foreground">
              {m.feature_passkeys_desc()}
            </span>
          </div>

          <h1 className="text-4xl md:text-6xl font-semibold tracking-tight mb-6 text-balance">
            {m.home_hero_title_1()}
            <span className="text-primary">{m.home_hero_title_2()}</span>
          </h1>

          <p className="text-lg md:text-xl text-muted-foreground mb-10 max-w-3xl mx-auto leading-relaxed text-balance">
            {m.home_hero_subtitle()}
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            {user ? (
              <Link to="/settings">
                <Button size="lg" className="h-11 px-6 text-base">
                  {m.button_manage_settings()}
                </Button>
              </Link>
            ) : (
              <>
                <Link to="/login">
                  <Button size="lg" className="h-11 px-6 text-base">
                    {m.button_login_now()}
                  </Button>
                </Link>
                <Link to="/register">
                  <Button
                    variant="outline"
                    size="lg"
                    className="h-11 px-6 text-base"
                  >
                    {m.button_create_account()}
                  </Button>
                </Link>
              </>
            )}
          </div>
        </div>

        {/* Abstract Background Elements */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10 pointer-events-none">
          <div className="absolute top-[-12%] right-[-6%] w-120 h-120 bg-primary/5 rounded-full blur-3xl opacity-60" />
          <div className="absolute bottom-[-12%] left-[-8%] w-140 h-140 bg-chart-2/10 rounded-full blur-3xl opacity-60" />
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-secondary/40">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-semibold mb-4 tracking-tight">
              {m.why_beaconauth_title()}
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg text-balance">
              {m.why_beaconauth_desc()}
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <Card className="border border-border/60 bg-card/70 shadow-xs hover:bg-card/90 transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-6 text-primary">
                  <KeyRound className="h-7 w-7" />
                </div>
                <h3 className="text-lg font-semibold mb-3">
                  {m.card_multi_auth_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_multi_auth_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="border border-border/60 bg-card/70 shadow-xs hover:bg-card/90 transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-xl bg-chart-2/15 flex items-center justify-center mb-6 text-chart-2">
                  <Shield className="h-7 w-7" />
                </div>
                <h3 className="text-lg font-semibold mb-3">
                  {m.card_enterprise_security_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_enterprise_security_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="border border-border/60 bg-card/70 shadow-xs hover:bg-card/90 transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-xl bg-chart-1/15 flex items-center justify-center mb-6 text-chart-1">
                  <Gamepad2 className="h-7 w-7" />
                </div>
                <h3 className="text-lg font-semibold mb-3">
                  {m.card_seamless_integration_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_seamless_integration_desc()}
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative overflow-hidden">
        <div className="container mx-auto px-6">
          <div className="bg-card/90 border border-border/70 rounded-2xl p-10 md:p-16 text-center relative overflow-hidden">
            <div className="relative z-10 max-w-3xl mx-auto">
              <h2 className="text-3xl md:text-4xl font-semibold mb-4 tracking-tight">
                {m.cta_title()}
              </h2>
              <p className="text-muted-foreground text-lg md:text-xl mb-8 max-w-2xl mx-auto">
                {m.cta_desc()}
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button size="lg" variant="outline" className="h-11 px-6">
                    <Github className="mr-2 h-5 w-5" />
                    {m.button_view_github()}
                  </Button>
                </a>
                <Link to="/login">
                  <Button size="lg" className="h-11 px-6">
                    {m.button_try_demo()}
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-border bg-background">
        <div className="container mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <BeaconIcon className="w-8 h-8 text-muted-foreground" />
              <div className="flex flex-col">
                <span className="font-semibold text-foreground">
                  {m.app_name()}
                </span>
                <span className="text-xs text-muted-foreground">
                  © 2026 Summpot
                </span>
              </div>
            </div>
            <div className="flex items-center gap-8 text-sm text-muted-foreground font-medium">
              <span>{m.footer_open_source()}</span>
              <span>{m.footer_license()}</span>
              <a
                href="https://github.com/Summpot/beacon_auth"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-primary transition-colors"
              >
                {m.footer_contribute()}
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: HomePage,
});
