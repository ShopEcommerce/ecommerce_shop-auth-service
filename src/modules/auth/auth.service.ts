import { AuthRepository } from './auth.repository';
import { BadRequestError, ForbiddenError, UnauthorizedError } from '@teleshop/common';
import { Password } from '../../utils/password';
import { AuthMessages } from '../../helpers/messages';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const MAX_FAILED_ATTEMPTS = parseInt(process.env.MAX_FAILED_ATTEMPTS!, 10);
const LOCK_TIME_MINUTES = parseInt(process.env.LOCK_TIME_MINUTES!, 10);
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS!, 10);

export class AuthService {
  static async signup(
    email: string,
    password: string,
    ipAddress: string,
    userAgent: string,
    correlationId?: string,
  ) {
    const existingUser = await AuthRepository.findByEmail(email);
    if (existingUser) throw new BadRequestError(AuthMessages.MSG_14.message);

    const hashedPassword = await Password.toHash(password);

    const user = await AuthRepository.createUserWithOutbox(
      {
        email,
        password: hashedPassword,
      },
      correlationId,
    );

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: email,
      action: 'SIGNUP_PENDING_VERIFICATION',
      ipAddress,
      userAgent,
    });

    return { user: { id: user.id, email: user.email, role: user.role, status: user.status } };
  }

  static async signin(email: string, password: string, ipAddress: string, userAgent: string) {
    const user = await AuthRepository.findByEmail(email);
    if (!user) {
      AuthRepository.createAuditLog({
        emailAttempt: email,
        action: 'SIGNIN_FAILED_NO_USER',
        ipAddress,
        userAgent,
      });
      throw new BadRequestError(AuthMessages.MSG_02.message);
    }

    if (user.status === 'PENDING') {
      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: 'SIGNIN_FAILED_EMAIL_NOT_VERIFIED',
        ipAddress,
        userAgent,
      });
      throw new ForbiddenError(AuthMessages.MSG_17.message);
    }

    if (user.status === 'BANNED') {
      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: 'SIGNIN_FAILED_USER_BANNED',
        ipAddress,
        userAgent,
      });
      throw new BadRequestError(AuthMessages.MSG_15.message);
    }

    if (user.status === 'SUSPENDED') {
      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: 'SIGNIN_FAILED_USER_SUSPENDED',
        ipAddress,
        userAgent,
      });
      throw new BadRequestError('Your account is suspended');
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: 'SIGNIN_BLOCKED',
        ipAddress,
        userAgent,
      });
      throw new BadRequestError(AuthMessages.MSG_03.message);
    }

    const passwordsMatch = await Password.compare(user.password, password);

    if (!passwordsMatch) {
      const failedAttempts = user.failedLoginAttempts + 1;
      let lockedUntil = null;
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        lockedUntil = new Date(Date.now() + LOCK_TIME_MINUTES * 60 * 1000);
      }

      await AuthRepository.updateUser(user.id, {
        failedLoginAttempts: failedAttempts,
        lockedUntil,
      });

      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: 'SIGNIN_FAILED_WRONG_PASS',
        ipAddress,
        userAgent,
      });

      throw new BadRequestError(AuthMessages.MSG_02.message);
    }

    if (user.failedLoginAttempts > 0) {
      await AuthRepository.updateUser(user.id, {
        failedLoginAttempts: 0,
        lockedUntil: null,
      });
    }

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: email,
      action: 'SIGNIN_SUCCESS',
      ipAddress,
      userAgent,
    });

    return this.generateAuthTokens(user);
  }

  static async verifyEmail(token: string, correlationId?: string) {
    const user = await AuthRepository.verifyEmailToken(token, correlationId);

    if (!user) {
      throw new BadRequestError(AuthMessages.MSG_09.message);
    }

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: user.email,
      action: 'EMAIL_VERIFIED_SUCCESS',
    });

    return { id: user.id, email: user.email, role: user.role, status: user.status };
  }

  static async signout(userId: string, refreshToken?: string) {
    if (refreshToken) {
      await AuthRepository.deleteRefreshToken(refreshToken);
    } else {
      await AuthRepository.deleteAllRefreshTokens(userId);
    }
  }

  static async refreshAuthToken(oldRefreshToken: string, ipAddress: string, userAgent: string) {
    const hashedOldToken = crypto.createHash('sha256').update(oldRefreshToken).digest('hex');
    const savedToken = await AuthRepository.findRefreshToken(hashedOldToken);

    if (!savedToken || savedToken.expiresAt < new Date()) {
      if (savedToken) await AuthRepository.deleteRefreshToken(hashedOldToken);
      throw new UnauthorizedError();
    }

    await AuthRepository.deleteRefreshToken(hashedOldToken);
    AuthRepository.createAuditLog({
      userId: savedToken.userId,
      emailAttempt: savedToken.user.email,
      action: 'TOKEN_REFRESHED',
      ipAddress,
      userAgent,
    });

    return this.generateAuthTokens(savedToken.user);
  }

  static async forgotPassword(email: string, correlationId?: string) {
    const user = await AuthRepository.findByEmail(email);

    if (!user) {
      AuthRepository.createAuditLog({
        emailAttempt: email,
        action: 'FORGOT_PASSWORD_REQUESTED_NOT_FOUND',
      });
      return;
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await AuthRepository.createPasswordResetToken(user.id, hashedToken, expiresAt);

    await AuthRepository.createPasswordResetOutboxEvent(
      user.id,
      user.email,
      resetToken,
      correlationId,
    );

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: email,
      action: 'FORGOT_PASSWORD_TOKEN_GENERATED',
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const resetRecord = await AuthRepository.findPasswordResetToken(hashedToken);

    if (!resetRecord || resetRecord.expiresAt < new Date()) {
      throw new BadRequestError(AuthMessages.MSG_09.message);
    }

    const newHashedPassword = await Password.toHash(newPassword);
    await AuthRepository.updateUser(resetRecord.userId, { password: newHashedPassword });

    await AuthRepository.deletePasswordResetToken(resetRecord.id);

    AuthRepository.createAuditLog({
      userId: resetRecord.userId,
      emailAttempt: resetRecord.user.email,
      action: 'PASSWORD_RESET_SUCCESS',
    });
  }

  static async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);

    const passwordsMatch = await Password.compare(user.password, oldPassword);
    if (!passwordsMatch) throw new BadRequestError(AuthMessages.MSG_02.message);

    const hashedPassword = await Password.toHash(newPassword);
    await AuthRepository.updateUser(userId, { password: hashedPassword });

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: user.email,
      action: 'PASSWORD_CHANGED',
    });
  }

  private static async generateAuthTokens(user: any) {
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: '15m' },
    );

    const plainRefreshToken = crypto.randomBytes(40).toString('hex');
    const hashedRefreshToken = crypto.createHash('sha256').update(plainRefreshToken).digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_DAYS);

    await AuthRepository.saveRefreshToken(user.id, hashedRefreshToken, expiresAt);

    const userResponse = { id: user.id, email: user.email, role: user.role };
    return { user: userResponse, accessToken, refreshToken: plainRefreshToken };
  }

  // =====================
  // ADMIN FUNCTIONS
  // =====================

  static async createUserByAdmin(
    email: string,
    password: string,
    role: string,
    status: string,
    adminId: string,
  ) {
    const existingUser = await AuthRepository.findByEmail(email);
    if (existingUser) throw new BadRequestError(AuthMessages.MSG_14.message);

    const hashedPassword = await Password.toHash(password);
    const user = await AuthRepository.createUser({
      email,
      password: hashedPassword,
      role: role as any,
      status: status as any,
    });

    AuthRepository.createAuditLog({
      userId: adminId,
      emailAttempt: email,
      action: 'USER_CREATED_BY_ADMIN',
    });

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  static async listUsers(
    page: number,
    limit: number,
    filters?: { role?: string; status?: string },
  ) {
    return AuthRepository.listUsers(page, limit, filters);
  }

  static async getUserById(userId: string) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);
    return user;
  }

  static async updateUser(
    userId: string,
    adminId: string,
    data: { role?: string; status?: string },
  ) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);

    const updateData: any = {};
    if (data.role) updateData.role = data.role;
    if (data.status) {
      updateData.status = data.status;
      if (data.status === 'BANNED') {
        updateData.bannedAt = new Date();
        updateData.bannedBy = adminId;
      }
    }

    const updated = await AuthRepository.updateUser(userId, updateData);

    AuthRepository.createAuditLog({
      userId: adminId,
      emailAttempt: user.email,
      action: `USER_UPDATED_BY_ADMIN`,
      ipAddress: undefined,
      userAgent: undefined,
    });

    return updated;
  }

  static async banUser(userId: string, banReason: string, adminId: string) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);

    if (user.status === 'BANNED') {
      throw new BadRequestError(AuthMessages.MSG_15.message);
    }

    const updated = await AuthRepository.updateUser(userId, {
      status: 'BANNED',
      bannedAt: new Date(),
      banReason,
      bannedBy: adminId,
    });

    // Delete all refresh tokens to force user to logout
    await AuthRepository.deleteAllRefreshTokens(userId);

    AuthRepository.createAuditLog({
      userId: adminId,
      emailAttempt: user.email,
      action: 'USER_BANNED_BY_ADMIN',
      ipAddress: undefined,
      userAgent: undefined,
    });

    // TODO: Emit UserBanned event for notification
    // await AuthRepository.createUserBannedOutboxEvent(userId, user.email, banReason);

    return updated;
  }

  static async unbanUser(userId: string, adminId: string) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);

    if (user.status !== 'BANNED') {
      throw new BadRequestError(AuthMessages.MSG_15.message);
    }

    const updated = await AuthRepository.updateUser(userId, {
      status: 'ACTIVE',
      bannedAt: null,
      banReason: null,
      bannedBy: null,
    });

    AuthRepository.createAuditLog({
      userId: adminId,
      emailAttempt: user.email,
      action: 'USER_UNBANNED_BY_ADMIN',
      ipAddress: undefined,
      userAgent: undefined,
    });

    // TODO: Emit UserUnbanned event for notification

    return updated;
  }

  static async deleteUser(userId: string, adminId: string) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError(AuthMessages.MSG_14.message);

    const updated = await AuthRepository.updateUser(userId, {
      status: 'SUSPENDED',
      password: 'DELETED',
    });

    await AuthRepository.deleteAllRefreshTokens(userId);
    await AuthRepository.deletePasswordResetTokenByUserId(userId);

    AuthRepository.createAuditLog({
      userId: adminId,
      emailAttempt: user.email,
      action: 'USER_DELETED_BY_ADMIN',
      ipAddress: undefined,
      userAgent: undefined,
    });

    return updated;
  }

  static async getAuditLogs(
    page: number,
    limit: number,
    filters?: { userId?: string; action?: string },
  ) {
    return AuthRepository.getAuditLogs(page, limit, filters);
  }
}
