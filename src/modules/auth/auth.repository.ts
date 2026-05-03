import { prisma } from "../../db/prisma";
import { Prisma } from "@prisma/client";

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
      .catch((err) => console.error("Lỗi AuditLog:", err));
  }

  static async saveRefreshToken(
    userId: string,
    token: string,
    expiresAt: Date,
  ) {
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
}
