import request from 'supertest';
import { app } from '../../../app';
import { AuthRepository } from '../auth.repository';
import { Password } from '../../../utils/password';

jest.mock('../auth.repository');

// Force deterministic Password behavior for signin tests.
// NOTE: We override the mock in each test via (Password.compare as jest.Mock).mockResolvedValue(...)
jest.mock('../../../utils/password', () => ({
  Password: {
    toHash: jest.fn(async (password: string) => `hashed:${password}`),
    compare: jest.fn(),
  },
}));

describe('Auth API Endpoints', () => {
  describe('POST /api/users/signup', () => {
    it('returns 201 and tokens when signup is successful', async () => {
      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue(null);

      (AuthRepository.createUserWithOutbox as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        role: 'CUSTOMER',
      });

      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);
      (AuthRepository.saveRefreshToken as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          email: 'test@teleshop.com',
          password: 'Password123!',
        })
        .expect(201);

      expect(response.body.message).toEqual('Signup successful');

      const user = response.body?.data;
      expect(user).toHaveProperty('id');
      expect(user.email).toEqual('test@teleshop.com');
      expect(response.get('Set-Cookie')).toBeDefined();
    });

    it('returns 400 if email is already in use', async () => {
      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue({
        id: 'user-456',
        email: 'test@teleshop.com',
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          email: 'test@teleshop.com',
          password: 'Password123!',
        })
        .expect(400);

      expect(response.body[0].message).toEqual('Email is already in use');
    });
  });

  describe('POST /api/auth/signin', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      (AuthRepository.findByEmail as jest.Mock).mockReset();
    });

    it('returns 200 when signin is successful', async () => {
      jest.setTimeout(20000);

      (Password.compare as jest.Mock).mockResolvedValue(true);

      const plainPassword = 'Password123!';
      const hashedPassword = await Password.toHash(plainPassword);

      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        password: hashedPassword,
        failedLoginAttempts: 0,
        lockedUntil: null,
        status: 'ACTIVE',
      });

      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);
      (AuthRepository.saveRefreshToken as jest.Mock).mockResolvedValue(true);
      (AuthRepository.updateUser as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/api/auth/signin')
        .send({
          email: 'test@teleshop.com',
          password: plainPassword,
        })
        .expect(200);

      expect(response.body.message).toEqual('Signin successful');

      const user = response.body?.data?.user ?? response.body?.data ?? response.body?.user;
      expect(user).toHaveProperty('id');
    });

    it('returns 400 if password is incorrect', async () => {
      (Password.compare as jest.Mock).mockResolvedValue(false);

      const hashedPassword = await Password.toHash('CorrectPassword123!');

      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        password: hashedPassword,
        failedLoginAttempts: 0,
        lockedUntil: null,
        status: 'ACTIVE',
      });

      (AuthRepository.updateUser as jest.Mock).mockResolvedValue(true);
      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);

      await request(app)
        .post('/api/auth/signin')
        .send({
          email: 'test@teleshop.com',
          password: 'WrongPassword!',
        })
        .expect(400);
    });
  });
});
