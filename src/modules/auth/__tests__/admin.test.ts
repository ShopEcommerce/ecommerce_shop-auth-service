import request from 'supertest';
import { app } from '../../../app';
import { AuthRepository } from '../auth.repository';
import jwt from 'jsonwebtoken';

jest.mock('../auth.repository');

// Mock currentUser middleware to inject admin user
jest.mock('@teleshop/common', () => ({
  ...jest.requireActual('@teleshop/common'),
  currentUser: (req: any, res: any, next: any) => {
    // In this test we set Cookie: jwt=<token> (no cookie-session).
    const cookieHeader = req.headers?.cookie || '';
    const match = /(?:^|;\s*)jwt=([^;]+)/.exec(cookieHeader);
    const token = match ? decodeURIComponent(match[1]) : req.session?.jwt;

    if (token) {
      try {
        req.currentUser = jwt.verify(token, process.env.JWT_SECRET || 'test-secret');
      } catch (_err) {
        // Token invalid
      }
    }
    next();
  },
  requireAuth: (req: any, res: any, next: any) => {
    if (!req.currentUser) {
      return res.status(401).send({ errors: [{ message: 'Not authorized' }] });
    }
    next();
  },
  asyncHandler: (fn: any) => (req: any, res: any, next: any) => fn(req, res, next).catch(next),
}));

describe('Auth Admin API Endpoints', () => {
  const adminToken = jwt.sign(
    { id: 'admin-123', email: 'admin@teleshop.com', role: 'ADMIN' },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '15m' },
  );

  describe('GET /api/auth/admin/users', () => {
    it('returns 200 and list of users when called by admin', async () => {
      (AuthRepository.listUsers as jest.Mock).mockResolvedValue({
        users: [
          {
            id: 'user-1',
            email: 'customer@teleshop.com',
            role: 'CUSTOMER',
            status: 'ACTIVE',
            createdAt: new Date(),
            bannedAt: null,
            banReason: null,
          },
        ],
        total: 1,
        page: 1,
        limit: 20,
        totalPages: 1,
      });

      const response = await request(app)
        .get('/api/auth/admin/users')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(200);

      expect(response.body.users).toHaveLength(1);
      expect(response.body.total).toBe(1);
    });
  });

  describe('GET /api/auth/admin/users/:id', () => {
    it('returns 200 and user details', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
        role: 'CUSTOMER',
        status: 'ACTIVE',
        createdAt: new Date(),
      });

      const response = await request(app)
        .get('/api/auth/admin/users/user-123')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(200);

      expect(response.body.id).toBe('user-123');
      expect(response.body.email).toBe('customer@teleshop.com');
    });

    it('returns 400 if user not found', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue(null);

      await request(app)
        .get('/api/auth/admin/users/nonexistent')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(400);
    });
  });

  describe('PUT /api/auth/admin/users/:id/ban', () => {
    it('returns 200 and bans user successfully', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
        status: 'ACTIVE',
      });

      (AuthRepository.updateUser as jest.Mock).mockResolvedValue({
        id: 'user-123',
        status: 'BANNED',
        bannedAt: new Date(),
        banReason: 'Violated terms of service',
      });

      (AuthRepository.deleteAllRefreshTokens as jest.Mock).mockResolvedValue(true);
      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .put('/api/auth/admin/users/user-123/ban')
        .set('Cookie', `jwt=${adminToken}`)
        .send({
          reason: 'Violated terms of service',
        })
        .expect(200);

      expect(response.body.message).toBe('User banned successfully');
      expect(response.body.user.status).toBe('BANNED');
    });

    it('returns 400 if user already banned', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
        status: 'BANNED',
      });

      await request(app)
        .put('/api/auth/admin/users/user-123/ban')
        .set('Cookie', `jwt=${adminToken}`)
        .send({
          reason: 'Violated terms of service',
        })
        .expect(400);
    });
  });

  describe('PUT /api/auth/admin/users/:id/unban', () => {
    it('returns 200 and unbans user successfully', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
        status: 'BANNED',
      });

      (AuthRepository.updateUser as jest.Mock).mockResolvedValue({
        id: 'user-123',
        status: 'ACTIVE',
        bannedAt: null,
        banReason: null,
      });

      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .put('/api/auth/admin/users/user-123/unban')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(200);

      expect(response.body.message).toBe('User unbanned successfully');
      expect(response.body.user.status).toBe('ACTIVE');
    });

    it('returns 400 if user is not banned', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
        status: 'ACTIVE',
      });

      await request(app)
        .put('/api/auth/admin/users/user-123/unban')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(400);
    });
  });

  describe('POST /api/auth/admin/users/:id/delete', () => {
    it('returns 200 and soft deletes user', async () => {
      (AuthRepository.findById as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'customer@teleshop.com',
      });

      (AuthRepository.updateUser as jest.Mock).mockResolvedValue({
        id: 'user-123',
        status: 'SUSPENDED',
      });

      (AuthRepository.deleteAllRefreshTokens as jest.Mock).mockResolvedValue(true);
      (AuthRepository.deletePasswordResetTokenByUserId as jest.Mock).mockResolvedValue(true);
      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .delete('/api/auth/admin/users/user-123')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(200);

      expect(response.body.message).toBe('User deleted successfully');
    });
  });

  describe('GET /api/auth/admin/audit-logs', () => {
    it('returns 200 and audit logs', async () => {
      (AuthRepository.getAuditLogs as jest.Mock).mockResolvedValue({
        logs: [
          {
            id: 'log-1',
            userId: 'user-123',
            action: 'SIGNIN_SUCCESS',
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 20,
        totalPages: 1,
      });

      const response = await request(app)
        .get('/api/auth/admin/audit-logs')
        .set('Cookie', `jwt=${adminToken}`)
        .expect(200);

      expect(response.body.logs).toHaveLength(1);
      expect(response.body.total).toBe(1);
    });
  });

  describe('Authorization checks', () => {
    it('returns 403 when non-admin tries to access admin endpoints', async () => {
      const customerToken = jwt.sign(
        { id: 'customer-1', email: 'customer@teleshop.com', role: 'CUSTOMER' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '15m' },
      );

      await request(app)
        .get('/api/auth/admin/users')
        .set('Cookie', `jwt=${customerToken}`)
        .expect(403);
    });
  });
});
