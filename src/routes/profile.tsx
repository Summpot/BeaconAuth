import { createFileRoute, redirect } from '@tanstack/react-router';
import { z } from 'zod';

const searchParamsSchema = z.object({
  status: z.enum(['success', 'error']).optional(),
  message: z.string().optional(),
});

export const Route = createFileRoute('/profile')({
  validateSearch: searchParamsSchema,
  beforeLoad: ({ search }) => {
    throw redirect({
      to: '/settings',
      search,
    });
  },
});
