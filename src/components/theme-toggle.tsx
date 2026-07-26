import { Moon, Sun } from 'lucide-react';
import { useTheme } from '@/components/theme-provider';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import * as m from '@/paraglide/messages';

export function ThemeToggle() {
  const { setTheme } = useTheme();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          {/* Both icons share one cell so the cross-fade stays centred. */}
          <span className="relative flex size-6 items-center justify-center">
            <Sun className="absolute size-6 rotate-0 scale-100 transition-transform duration-200 ease-emphasized dark:-rotate-90 dark:scale-0" />
            <Moon className="absolute size-6 rotate-90 scale-0 transition-transform duration-200 ease-emphasized dark:rotate-0 dark:scale-100" />
          </span>
          <span className="sr-only">{m.theme_toggle()}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setTheme('light')}>
          {m.theme_light()}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('dark')}>
          {m.theme_dark()}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('system')}>
          {m.theme_system()}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
