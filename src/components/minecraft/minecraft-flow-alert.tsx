import { Gamepad2 } from 'lucide-react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import * as m from '@/paraglide/messages';

export function MinecraftFlowAlert({ title }: { title: string }) {
  return (
    <Alert>
      <Gamepad2 className="h-4 w-4" />
      <AlertDescription>
        <div className="space-y-2">
          <span className="text-primary font-medium">{title}</span>
          <p className="text-sm text-muted-foreground">
            {m.minecraft_flow_desc()}
          </p>
        </div>
      </AlertDescription>
    </Alert>
  );
}
