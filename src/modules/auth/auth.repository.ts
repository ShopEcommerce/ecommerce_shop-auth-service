import { prisma } from '../../db/prisma';
import { Prisma } from '@prisma/client';
import {
  Subjects,
  UserPasswordResetRequestedEvent,
  UserRegisteredEvent,
  UserRole,
  UserVerifiedEvent,
} from '@teleshop/common';
import crypto from 'crypto';
import pino from 'pino';

const logger = pino();

export class AuthRepository {
  static async findByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }
  static async findById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }
  static async createUser(data: Prisma.UserCreateInput) {
    return prisma.user.create({ data });
  }
  static async updateUser(id: string, data: Prisma.UserUpdateInput) {
    return prisma.user.update({ where: { id }, data });
  }

  static async createAuditLog(data: {
    userId?: string;
    emailAttempt: string;
    action: string;
    ipAddress?: string;
    userAgent?: string;
  }) {
    prisma.auditLog
      .create({ data })
      .catch((err) => logger.error({ err, data }, 'Failed to create AuditLog'));
  }

  static async saveRefreshToken(userId: string, token: string, expiresAt: Date) {
    return prisma.refreshToken.create({
      data: { userId, token, expiresAt },
    });
  }

  static async findRefreshToken(token: string) {
    return prisma.refreshToken.findUnique({
      where: { token },
      include: { user: true },
    });
  }

  static async deleteRefreshToken(token: string) {
    return prisma.refreshToken.delete({ where: { token } }).catch(() => null);
  }

  static async deleteAllRefreshTokens(userId: string) {
    return prisma.refreshToken.deleteMany({ where: { userId } });
  }

  static async createUserWithOutbox(data: Prisma.UserCreateInput, correlationId?: string) {
    return prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          ...data,
          status: 'PENDING',
        },
      });

      const verificationToken = crypto.randomBytes(32).toString('hex');
      const hashedVerificationToken = crypto
        .createHash('sha256')
        .update(verificationToken)
        .digest('hex');
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

      await tx.emailVerificationToken.create({
        data: {
          userId: user.id,
          token: hashedVerificationToken,
          expiresAt,
        },
      });

      const eventPayload: UserRegisteredEvent['data'] = {
        id: crypto.randomUUID(),
        type: Subjects.UserRegistered,
        occurredAt: new Date().toISOString(),
        version: 1,
        correlationId,
        userId: user.id,
        email: user.email,
        role: user.role,
        verificationToken,
      };

      await tx.outboxEvent.create({
        data: {
          subject: Subjects.UserRegistered,
          payload: eventPayload as any,
        },
      });

      return user;
    });
  }

  static async findEmailVerificationToken(token: string) {
    return prisma.emailVerificationToken.findUnique({
      where: { token },
      include: { user: true },
    });
  }

  static async deleteEmailVerificationToken(id: string) {
    return prisma.emailVerificationToken.delete({ where: { id } });
  }

  static async createUserVerifiedOutboxEvent(
    userId: string,
    email: string,
    role: UserRole,
    correlationId?: string,
  ) {
    const eventPayload: UserVerifiedEvent['data'] = {
      id: crypto.randomUUID(),
      type: Subjects.UserVerified,
      occurredAt: new Date().toISOString(),
      version: 1,
      correlationId,
      userId,
      email,
      role,
    };

    return prisma.outboxEvent.create({
      data: {
        subject: Subjects.UserVerified,
        payload: eventPayload as any,
      },
    });
  }

  static async verifyEmailToken(token: string, correlationId?: string) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    return prisma.$transaction(async (tx) => {
      const verificationRecord = await tx.emailVerificationToken.findUnique({
        where: { token: hashedToken },
        include: { user: true },
      });

      if (!verificationRecord || verificationRecord.expiresAt < new Date()) {
        return null;
      }

      const user = await tx.user.update({
        where: { id: verificationRecord.userId },
        data: { status: 'ACTIVE' },
      });

      await tx.emailVerificationToken.delete({ where: { id: verificationRecord.id } });

      const eventPayload: UserVerifiedEvent['data'] = {
        id: crypto.randomUUID(),
        type: Subjects.UserVerified,
        occurredAt: new Date().toISOString(),
        version: 1,
        correlationId,
        userId: user.id,
        email: user.email,
        role: user.role,
      };

      await tx.outboxEvent.create({
        data: {
          subject: Subjects.UserVerified,
          payload: eventPayload as any,
        },
      });

      return user;
    });
  }

  static async createPasswordResetToken(userId: string, token: string, expiresAt: Date) {
    await prisma.passwordResetToken.deleteMany({ where: { userId } });
    return prisma.passwordResetToken.create({
      data: { userId, token, expiresAt },
    });
  }

  static async findPasswordResetToken(token: string) {
    return prisma.passwordResetToken.findUnique({
      where: { token },
      include: { user: true },
    });
  }

  static async deletePasswordResetToken(id: string) {
    return prisma.passwordResetToken.delete({ where: { id } });
  }

  static async createPasswordResetOutboxEvent(
    userId: string,
    email: string,
    rawToken: string,
    correlationId?: string,
  ) {
    const eventPayload: UserPasswordResetRequestedEvent['data'] = {
      id: crypto.randomUUID(),
      type: Subjects.UserPasswordResetRequested,
      occurredAt: new Date().toISOString(),
      version: 1,
      correlationId,
      userId,
      email,
      resetToken: rawToken,
    };

    return prisma.outboxEvent.create({
      data: {
        subject: Subjects.UserPasswordResetRequested,
        payload: eventPayload as any,
      },
    });
  }

  // --- FUNCTIONS FOR OUTBOX WORKER TO SCAN DATABASE ---
  static async getPendingOutboxEvents() {
    return prisma.outboxEvent.findMany({
      where: { status: 'PENDING' },
      take: 20, // Scan 20 events at a time
      orderBy: { createdAt: 'asc' },
    });
  }

  static async markOutboxEventAsPublished(id: string) {
    return prisma.outboxEvent.update({
      where: { id },
      data: { status: 'PUBLISHED', processedAt: new Date() },
    });
  }

  static async markOutboxEventAsFailed(id: string, errorMsg: string) {
    return prisma.outboxEvent.update({
      where: { id },
      data: { status: 'FAILED', errorReason: errorMsg },
    });
  }

  // =====================
  // ADMIN FUNCTIONS
  // =====================

  static async listUsers(
    page: number,
    limit: number,
    filters?: { role?: string; status?: string },
  ) {
    const skip = (page - 1) * limit;

    const where: any = {};
    if (filters?.role) where.role = filters.role;
    if (filters?.status) where.status = filters.status;

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
          role: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          bannedAt: true,
          banReason: true,
          failedLoginAttempts: true,
          lockedUntil: true,
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.user.count({ where }),
    ]);

    return {
      users,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  static async deletePasswordResetTokenByUserId(userId: string) {
    return prisma.passwordResetToken.deleteMany({ where: { userId } });
  }

  static async getAuditLogs(
    page: number,
    limit: number,
    filters?: { userId?: string; action?: string },
  ) {
    const skip = (page - 1) * limit;

    const where: any = {};
    if (filters?.userId) where.userId = filters.userId;
    if (filters?.action) where.action = { contains: filters.action, mode: 'insensitive' };

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        skip,
        take: limit,
        include: {
          user: {
            select: { id: true, email: true },
          },
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.auditLog.count({ where }),
    ]);

    return {
      logs,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }
}
