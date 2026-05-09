import express, { RequestHandler } from 'express';
import { validateZod } from '../../middlewares/validate.middleware';
import {
  signupSchema,
  signinSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from './auth.schema';
import { AuthController } from './auth.controller';
import { asyncHandler, currentUser, requireAuth } from '@teleshop/common';

const router = express.Router();

const currentUserMw = currentUser as unknown as RequestHandler;
const requireAuthMw = requireAuth as unknown as RequestHandler;

// --- PUBLIC ROUTES ---
router.post('/signup', validateZod(signupSchema), asyncHandler(AuthController.signup));

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

export { router as authRouter };
