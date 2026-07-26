import { createFileRoute } from '@tanstack/react-router';
import { AlertTriangle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent } from '@/components/ui/card';
import * as m from '@/paraglide/messages';

function ErrorPage() {
  return (
    <div className="flex min-h-full items-center justify-center bg-surface p-4">
      <div className="w-full max-w-md">
        <Card className="rounded-xl">
          <CardContent className="p-8">
            <div className="text-center">
              <div className="mx-auto mb-6 flex size-20 items-center justify-center rounded-full bg-error-container text-on-error-container">
                <AlertTriangle className="size-10" />
              </div>
              <h1 className="mb-3 text-headline-sm text-on-surface">
                {m.error_page_invalid_request_title()}
              </h1>
              <p className="mb-6 text-body-lg text-on-surface-variant">
                {m.error_page_invalid_request_desc_line1()}
                <br />
                {m.error_page_invalid_request_desc_line2()}
              </p>
              <Alert variant="destructive" className="text-left">
                <AlertTriangle />
                <AlertDescription>
                  {m.error_page_missing_required_params()}
                </AlertDescription>
              </Alert>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/error')({
  component: ErrorPage,
});
