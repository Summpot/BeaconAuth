import { createFileRoute } from '@tanstack/react-router';
import { AlertTriangle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent } from '@/components/ui/card';
import * as m from '@/paraglide/messages';

function ErrorPage() {
  return (
    <div className="flex items-center justify-center min-h-full p-4">
      <div className="w-full max-w-md">
        <Card>
          <CardContent className="p-8">
            <div className="text-center">
              <div className="text-6xl mb-4">⚠️</div>
              <h1 className="text-2xl font-bold mb-4">
                {m.error_page_invalid_request_title()}
              </h1>
              <p className="text-muted-foreground mb-4">
                {m.error_page_invalid_request_desc_line1()}
                <br />
                {m.error_page_invalid_request_desc_line2()}
              </p>
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
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
