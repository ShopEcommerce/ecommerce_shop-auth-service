import { prisma } from '../../db/prisma';
import { Prisma } from '@prisma/client';
import { Subjects } from '@teleshop/common';
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
      const user = await tx.user.create({ data });

      const eventPayload = {
        id: crypto.randomUUID(),
        type: Subjects.UserRegistered,
        occurredAt: new Date().toISOString(),
        version: 1,
        correlationId: correlationId,

        userId: user.id,
        email: user.email,
        role: user.role,
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

  static async createPasswordResetOutboxEvent(userId: string, email: string, rawToken: string) {
    const eventPayload = {
      eventId: crypto.randomUUID(),
      type: Subjects.UserPasswordResetRequested,
      occurredAt: new Date().toISOString(),
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
}
