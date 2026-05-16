import express, { RequestHandler } from 'express';
import { validateZod } from '../../middlewares/validate.middleware';
import {
  signupSchema,
  verifyEmailSchema,
  signinSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  updateUserSchema,
  banUserSchema,
  listUsersSchema,
} from './auth.schema';
import { AuthController } from './auth.controller';
import { asyncHandler, currentUser, requireAuth } from '@teleshop/common';

const router = express.Router();

const currentUserMw = currentUser as unknown as RequestHandler;
const requireAuthMw = requireAuth as unknown as RequestHandler;

// Middleware to restrict to Admin role
const restrictToAdmin = (req: any, res: any, next: any) => {
  if (req.currentUser?.role !== 'ADMIN') {
    return res.status(403).send({ errors: [{ message: 'Access denied: Admin only' }] });
  }
  next();
};

// --- PUBLIC ROUTES ---
router.post('/signup', validateZod(signupSchema), asyncHandler(AuthController.signup));

router.get(
  '/verify-email',
  validateZod(verifyEmailSchema),
  asyncHandler(AuthController.verifyEmail as any),
);

router.post('/signin', validateZod(signinSchema), asyncHandler(AuthController.signin));

router.post('/refresh-token', asyncHandler(AuthController.refreshToken));

router.post(
  '/forgot-password',
  validateZod(forgotPasswordSchema),
  asyncHandler(AuthController.forgotPassword),
);

router.post(
  '/reset-password',
  validateZod(resetPasswordSchema),
  asyncHandler(AuthController.resetPassword),
);

// --- PROTECTED ROUTES ---
router.post(
  '/change-password',
  currentUserMw,
  requireAuthMw,
  validateZod(changePasswordSchema),
  asyncHandler(AuthController.changePassword),
);

router.get('/currentuser', currentUserMw, asyncHandler(AuthController.getCurrentUser));

router.post('/signout', currentUserMw, requireAuthMw, asyncHandler(AuthController.signout));

// --- ADMIN ROUTES ---
router.get(
  '/admin/users',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  validateZod(listUsersSchema),
  asyncHandler(AuthController.listUsers as any),
);

router.get(
  '/admin/users/:id',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  asyncHandler(AuthController.getUserById as any),
);

router.put(
  '/admin/users/:id',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  validateZod(updateUserSchema),
  asyncHandler(AuthController.updateUser as any),
);

router.put(
  '/admin/users/:id/ban',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  validateZod(banUserSchema),
  asyncHandler(AuthController.banUser as any),
);

router.put(
  '/admin/users/:id/unban',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  asyncHandler(AuthController.unbanUser as any),
);

router.delete(
  '/admin/users/:id',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  asyncHandler(AuthController.deleteUser as any),
);

router.get(
  '/admin/audit-logs',
  currentUserMw,
  requireAuthMw,
  restrictToAdmin,
  asyncHandler(AuthController.getAuditLogs),
);

export { router as authRouter };
