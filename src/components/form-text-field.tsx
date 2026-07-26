import type { AnyFieldApi } from '@tanstack/react-form';
import type { ComponentProps, ReactNode } from 'react';
import { TextField } from '@/components/ui/text-field';
import { getFieldErrorMessage } from '@/lib/errors';

type FormTextFieldProps = {
  field: AnyFieldApi;
  label: string;
  /** Rendered as the field's trailing icon (e.g. an info tooltip trigger). */
  labelAdornment?: ReactNode;
} & Omit<
  ComponentProps<typeof TextField>,
  | 'id'
  | 'name'
  | 'value'
  | 'onBlur'
  | 'onChange'
  | 'aria-invalid'
  | 'label'
  | 'errorText'
  | 'trailing'
>;

/**
 * Material Design 3 text field bound to a TanStack Form field.
 * The input id/name mirror the field name so autofill and labels keep working.
 */
export function FormTextField({
  field,
  label,
  labelAdornment,
  ...inputProps
}: FormTextFieldProps) {
  const isInvalid = field.state.meta.isTouched && !field.state.meta.isValid;
  const errorMessage = getFieldErrorMessage(field.state.meta.errors);

  return (
    <TextField
      id={field.name}
      name={field.name}
      label={label}
      value={field.state.value}
      onBlur={field.handleBlur}
      onChange={(event) => field.handleChange(event.target.value)}
      errorText={isInvalid && errorMessage ? errorMessage : undefined}
      trailing={labelAdornment}
      {...inputProps}
    />
  );
}
