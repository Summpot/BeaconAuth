import type { AnyFieldApi } from '@tanstack/react-form';
import type { ComponentProps, ReactNode } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { getFieldErrorMessage } from '@/lib/errors';
import { cn } from '@/lib/utils';

type FormTextFieldProps = {
  field: AnyFieldApi;
  label: string;
  srOnlyLabel?: boolean;
  /** Rendered inline next to the label (e.g. an info tooltip trigger). */
  labelAdornment?: ReactNode;
} & Omit<
  ComponentProps<typeof Input>,
  'id' | 'name' | 'value' | 'onBlur' | 'onChange' | 'aria-invalid'
>;

/**
 * Standard Label + Input + validation-error block for TanStack Form fields.
 * The input id/name mirror the field name so autofill and labels keep working.
 */
export function FormTextField({
  field,
  label,
  srOnlyLabel,
  labelAdornment,
  ...inputProps
}: FormTextFieldProps) {
  const isInvalid = field.state.meta.isTouched && !field.state.meta.isValid;
  const errorMessage = getFieldErrorMessage(field.state.meta.errors);

  return (
    <div className="space-y-2">
      {labelAdornment ? (
        <div className="flex items-center gap-2">
          <Label htmlFor={field.name}>{label}</Label>
          {labelAdornment}
        </div>
      ) : (
        <Label htmlFor={field.name} className={cn(srOnlyLabel && 'sr-only')}>
          {label}
        </Label>
      )}
      <Input
        id={field.name}
        name={field.name}
        value={field.state.value}
        onBlur={field.handleBlur}
        onChange={(event) => field.handleChange(event.target.value)}
        aria-invalid={isInvalid}
        {...inputProps}
      />
      {isInvalid && errorMessage ? (
        <p className="text-sm text-destructive">{errorMessage}</p>
      ) : null}
    </div>
  );
}
