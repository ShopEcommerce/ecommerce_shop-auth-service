import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import {
  SignupInput,
  SigninInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  ChangePasswordInput,
} from './auth.schema';

export class AuthController {
  
  static async signup(req: Request<{}, {}, SignupInput>, res: Response) {
    const { email, password } = req.body;

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const { user, accessToken, refreshToken } = await AuthService.signup(email, password, ipAddress, userAgent);

    req.session = { jwt: accessToken, refreshToken };

    res.status(201).send({ message: 'Signup successful', user });
  }

  static async signin(req: Request<{}, {}, SigninInput>, res: Response) {
    const { email, password } = req.body;

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const { user, accessToken, refreshToken } = await AuthService.signin(email, password, ipAddress, userAgent);

    req.session = { jwt: accessToken, refreshToken };
    res.status(200).send({ message: 'Signin successful', user });
  }

  static async signout(req: Request, res: Response) {
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

    const { accessToken, refreshToken } = await AuthService.refreshAuthToken(oldRefreshToken, ipAddress, userAgent);

    req.session = { jwt: accessToken, refreshToken };

    res.status(200).send({ message: 'Token refreshed successfully' });
  }

  static async forgotPassword(req: Request<{}, {}, ForgotPasswordInput>, res: Response) {
    const { email } = req.body;
    await AuthService.forgotPassword(email);
    
    res.status(200).send({ message: 'If the email exists, a reset link will be sent' });
  }

  static async resetPassword(req: Request<{}, {}, ResetPasswordInput>, res: Response) {
    const { token, newPassword } = req.body;
    await AuthService.resetPassword(token, newPassword);
    
    res.status(200).send({ message: 'Password has been reset successfully' });
  }

  static async changePassword(req: Request<{}, {}, ChangePasswordInput>, res: Response) {
    const { oldPassword, newPassword } = req.body;
    
    const userId = req.currentUser!.id; 
    
    await AuthService.changePassword(userId, oldPassword, newPassword);
    res.status(200).send({ message: 'Password changed successfully' });
  }

  static async getCurrentUser(req: Request, res: Response) {
    res.status(200).send({ currentUser: req.currentUser || null });
  }
}