import { AuthRepository } from "./auth.repository";
import { BadRequestError, rabbitmqWrapper, UnauthorizedError } from "@teleshop/common";
import { Password } from "../../utils/password";
import { UserRegisteredPublisher } from "../../events/publishers/user-registered-publisher";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const MAX_FAILED_ATTEMPTS = parseInt(process.env.MAX_FAILED_ATTEMPTS!, 10);
const LOCK_TIME_MINUTES = parseInt(process.env.LOCK_TIME_MINUTES!, 10);
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS!, 10);

export class AuthService {
  static async signup(
    email: string,
    password: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const existingUser = await AuthRepository.findByEmail(email);
    if (existingUser) throw new BadRequestError("Email is already in use");

    const hashedPassword = await Password.toHash(password);

    const user = await AuthRepository.createUser({
      email,
      password: hashedPassword,
    });

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: email,
      action: "SIGNUP_SUCCESS",
      ipAddress,
      userAgent,
    });

    await new UserRegisteredPublisher(rabbitmqWrapper.channel).publish({
      id: crypto.randomUUID(),
      userId: user.id,
      email: user.email,
      role: user.role,
      version: 1,
      timestamp: new Date().toISOString(),
    });

    return this.generateAuthTokens(user);
  }

  static async signin(
    email: string,
    password: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const user = await AuthRepository.findByEmail(email);
    if (!user) {
      AuthRepository.createAuditLog({
        emailAttempt: email,
        action: "SIGNIN_FAILED_NO_USER",
        ipAddress,
        userAgent,
      });
      throw new BadRequestError("Invalid credentials");
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      AuthRepository.createAuditLog({
        userId: user.id,
        emailAttempt: email,
        action: "SIGNIN_BLOCKED",
        ipAddress,
        userAgent,
      });
      throw new BadRequestError(
        `Account locked until ${user.lockedUntil.toLocaleTimeString()}`,
      );
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
        action: "SIGNIN_FAILED_WRONG_PASS",
        ipAddress,
        userAgent,
      });

      throw new BadRequestError("Invalid credentials");
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
      action: "SIGNIN_SUCCESS",
      ipAddress,
      userAgent,
    });

    return this.generateAuthTokens(user);
  }

  static async signout(userId: string, refreshToken?: string) {
    if (refreshToken) {
      await AuthRepository.deleteRefreshToken(refreshToken);
    } else {
      await AuthRepository.deleteAllRefreshTokens(userId);
    }
  }

  static async refreshAuthToken(
    oldRefreshToken: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const savedToken = await AuthRepository.findRefreshToken(oldRefreshToken);

    if (!savedToken || savedToken.expiresAt < new Date()) {
      if (savedToken) await AuthRepository.deleteRefreshToken(oldRefreshToken);
      throw new UnauthorizedError();
    }

    await AuthRepository.deleteRefreshToken(oldRefreshToken);
    AuthRepository.createAuditLog({
      userId: savedToken.userId,
      emailAttempt: savedToken.user.email,
      action: "TOKEN_REFRESHED",
      ipAddress,
      userAgent,
    });

    return this.generateAuthTokens(savedToken.user);
  }

  static async forgotPassword(email: string) {
    // TODO: Generate Reset Token -> Save to DB -> Send SendEmailEvent to RabbitMQ for Notification Service
    AuthRepository.createAuditLog({
      emailAttempt: email,
      action: "FORGOT_PASSWORD_REQUESTED",
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    // TODO: Validate Token -> Hash newPassword -> Update User DB
  }

  static async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    const user = await AuthRepository.findById(userId);
    if (!user) throw new BadRequestError("User not found");

    const passwordsMatch = await Password.compare(user.password, oldPassword);
    if (!passwordsMatch) throw new BadRequestError("Invalid old password");

    const hashedPassword = await Password.toHash(newPassword);
    await AuthRepository.updateUser(userId, { password: hashedPassword });

    AuthRepository.createAuditLog({
      userId: user.id,
      emailAttempt: user.email,
      action: "PASSWORD_CHANGED",
    });
  }

  private static async generateAuthTokens(user: any) {
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: '15m' } 
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_DAYS);

    await AuthRepository.saveRefreshToken(user.id, refreshToken, expiresAt);

    const userResponse = { id: user.id, email: user.email, role: user.role };
    return { user: userResponse, accessToken, refreshToken };
  }
}
