import { ApiError } from '@/utils/api';

export const getErrorMessage = (error: unknown, fallback: string) => {
  if (error instanceof ApiError) {
    const data = error.data as { message?: string } | undefined;
    return data?.message ?? fallback;
  }
  return fallback;
};

export const getFieldErrorMessage = (errors: Array<unknown> | undefined) => {
  const error = errors?.[0];
  if (!error) return '';
  if (typeof error === 'string') return error;
  if (typeof error === 'object' && 'message' in error) {
    return String((error as { message?: string }).message ?? '');
  }
  return '';
};
