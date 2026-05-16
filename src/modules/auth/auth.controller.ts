import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthMessages } from '../../helpers/messages';
import {
  SignupInput,
  VerifyEmailInput,
  SigninInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  ChangePasswordInput,
  UpdateUserInput,
  BanUserInput,
  ListUsersInput,
} from './auth.schema';

export class AuthController {
  static async signup(req: Request<unknown, unknown, SignupInput>, res: Response) {
    const { email, password } = req.body;

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const correlationId = req.correlationId;

    const { user } = await AuthService.signup(email, password, ipAddress, userAgent, correlationId);

    req.session = null;
    res.status(201).send(AuthMessages.buildSuccessResponse(AuthMessages.MSG_16, user));
  }

  static async verifyEmail(
    req: Request<unknown, unknown, unknown, VerifyEmailInput>,
    res: Response,
  ) {
    const { token } = req.query;
    const correlationId = req.correlationId;

    const user = await AuthService.verifyEmail(token, correlationId);

    res.status(200).send(AuthMessages.buildSuccessResponse(AuthMessages.MSG_13, user));
  }

  static async signin(req: Request<unknown, unknown, SigninInput>, res: Response) {
    const { email, password } = req.body;

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const { user, accessToken, refreshToken } = await AuthService.signin(
      email,
      password,
      ipAddress,
      userAgent,
    );

    req.session = { jwt: accessToken, refreshToken };
    res.status(200).send(AuthMessages.buildSuccessResponse(AuthMessages.MSG_04, user));
  }

  static async signout(req: Request<unknown, unknown, unknown>, res: Response) {
    const refreshToken = req.session?.refreshToken;
    const userId = req.currentUser?.id;

    if (userId) {
      await AuthService.signout(userId, refreshToken);
    }

    req.session = null;
    res.status(200).send({ message: 'Signout successful' });
  }

  static async refreshToken(req: Request, res: Response) {
    const oldRefreshToken = req.session?.refreshToken;
    if (!oldRefreshToken) {
      res.status(401).send({ errors: [{ message: 'Not authorized' }] });
      return;
    }

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const { accessToken, refreshToken } = await AuthService.refreshAuthToken(
      oldRefreshToken,
      ipAddress,
      userAgent,
    );

    req.session = { jwt: accessToken, refreshToken };

    res.status(200).send({ message: 'Token refreshed successfully' });
  }

  static async forgotPassword(req: Request<unknown, unknown, ForgotPasswordInput>, res: Response) {
    const { email } = req.body;
    const correlationId = req.correlationId;

    await AuthService.forgotPassword(email, correlationId);

    res.status(200).send({ message: 'If the email exists, a reset link will be sent' });
  }

  static async resetPassword(req: Request<unknown, unknown, ResetPasswordInput>, res: Response) {
    const { token, newPassword } = req.body;
    await AuthService.resetPassword(token, newPassword);

    res.status(200).send({ message: 'Password has been reset successfully' });
  }

  static async changePassword(req: Request<unknown, unknown, ChangePasswordInput>, res: Response) {
    const { oldPassword, newPassword } = req.body;

    const userId = req.currentUser!.id;

    await AuthService.changePassword(userId, oldPassword, newPassword);
    res.status(200).send({ message: 'Password changed successfully' });
  }

  static async getCurrentUser(req: Request, res: Response) {
    res.status(200).send({ currentUser: req.currentUser || null });
  }

  // =====================
  // ADMIN ENDPOINTS
  // =====================

  static async listUsers(req: Request<unknown, unknown, unknown, ListUsersInput>, res: Response) {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '20', 10);
    const filters = {
      role: req.query.role,
      status: req.query.status,
    };

    const result = await AuthService.listUsers(page, limit, filters);
    res.status(200).send(result);
  }

  static async getUserById(req: Request<{ id: string }>, res: Response) {
    const { id } = req.params;
    const user = await AuthService.getUserById(id);
    res.status(200).send(user);
  }

  static async updateUser(req: Request<{ id: string }, unknown, UpdateUserInput>, res: Response) {
    const { id } = req.params;
    const adminId = req.currentUser!.id;
    const updated = await AuthService.updateUser(id, adminId, req.body);
    res.status(200).send({ message: 'User updated successfully', user: updated });
  }

  static async banUser(req: Request<{ id: string }, unknown, BanUserInput>, res: Response) {
    const { id } = req.params;
    const { reason } = req.body;
    const adminId = req.currentUser!.id;

    const updated = await AuthService.banUser(id, reason, adminId);
    res.status(200).send({ message: 'User banned successfully', user: updated });
  }

  static async unbanUser(req: Request<{ id: string }>, res: Response) {
    const { id } = req.params;
    const adminId = req.currentUser!.id;

    const updated = await AuthService.unbanUser(id, adminId);
    res.status(200).send({ message: 'User unbanned successfully', user: updated });
  }

  static async deleteUser(req: Request<{ id: string }>, res: Response) {
    const { id } = req.params;
    const adminId = req.currentUser!.id;

    await AuthService.deleteUser(id, adminId);
    res.status(200).send({ message: 'User deleted successfully' });
  }

  static async getAuditLogs(req: Request<unknown, unknown, unknown, any>, res: Response) {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '20', 10);
    const filters = {
      userId: req.query.userId,
      action: req.query.action,
    };

    const result = await AuthService.getAuditLogs(page, limit, filters);
    res.status(200).send(result);
  }
}
