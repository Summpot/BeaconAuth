import { type ReactNode, useState } from 'react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import * as m from '@/paraglide/messages';

type ConfirmDialogProps = {
  /** Title of the dialog. */
  title: string;
  /** Description shown under the title. */
  description: string;
  /** Label for the confirm button (defaults to localized "Confirm"). */
  confirmLabel?: string;
  /** Label for the cancel button (defaults to localized "Cancel"). */
  cancelLabel?: string;
  /** Confirmation button styling. */
  destructive?: boolean;
  onConfirm: () => void;
  children: ReactNode;
};

/**
 * Accessible replacement for `window.confirm`: wraps children in a trigger,
 * renders an alert dialog with localized labels and keeps focus in the app.
 */
export function ConfirmDialog({
  title,
  description,
  confirmLabel,
  cancelLabel,
  destructive,
  onConfirm,
  children,
}: ConfirmDialogProps) {
  const [open, setOpen] = useState(false);

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>{children}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>
            {cancelLabel ?? m.confirm_dialog_cancel()}
          </AlertDialogCancel>
          <AlertDialogAction
            className={
              destructive
                ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
                : ''
            }
            onClick={() => {
              setOpen(false);
              onConfirm();
            }}
          >
            {confirmLabel ?? m.confirm_dialog_confirm()}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
