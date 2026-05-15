import { z } from 'zod';

// --- SCHEMAS ---

const passwordSchema = z
  .string({ error: 'Password is required' })
  .min(8, 'Password must be at least 8 characters long')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[\W_]/, 'Password must contain at least one special character');

export const signupSchema = z.object({
  body: z.object({
    email: z.string({ error: 'Email is required' }).email('Invalid email format'),
    password: passwordSchema,
  }),
});

export const signinSchema = z.object({
  body: z.object({
    email: z.string({ error: 'Email is required' }).email('Invalid email format'),
    password: z.string({ error: 'Password is required' }),
  }),
});

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.string({ error: 'Email is required' }).email('Invalid email format'),
  }),
});

export const resetPasswordSchema = z.object({
  body: z.object({
    token: z.string({ error: 'Reset token is required' }),
    newPassword: passwordSchema,
  }),
});

export const changePasswordSchema = z.object({
  body: z.object({
    oldPassword: z.string({ error: 'Old password is required' }),
    newPassword: passwordSchema,
  }),
});

// Admin APIs
export const updateUserSchema = z.object({
  body: z.object({
    role: z.enum(['CUSTOMER', 'SELLER', 'ADMIN']).optional(),
    status: z.enum(['ACTIVE', 'BANNED', 'SUSPENDED']).optional(),
  }),
});

export const banUserSchema = z.object({
  body: z.object({
    reason: z
      .string({ error: 'Ban reason is required' })
      .min(5, 'Reason must be at least 5 characters'),
  }),
});

export const listUsersSchema = z.object({
  query: z.object({
    page: z.string().regex(/^\d+$/).optional().default('1'),
    limit: z.string().regex(/^\d+$/).optional().default('20'),
    role: z.enum(['CUSTOMER', 'SELLER', 'ADMIN']).optional(),
    status: z.enum(['ACTIVE', 'BANNED', 'SUSPENDED']).optional(),
  }),
});

// --- TYPES EXPORT ---
export type SignupInput = z.infer<typeof signupSchema>['body'];
export type SigninInput = z.infer<typeof signinSchema>['body'];
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>['body'];
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>['body'];
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>['body'];
export type UpdateUserInput = z.infer<typeof updateUserSchema>['body'];
export type BanUserInput = z.infer<typeof banUserSchema>['body'];
export type ListUsersInput = z.infer<typeof listUsersSchema>['query'];
