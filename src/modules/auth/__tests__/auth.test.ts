import request from 'supertest';
import { app } from '../../../app';
import { AuthRepository } from '../auth.repository';
import { Password } from '../../../utils/password';

jest.mock('../auth.repository');

describe('Auth API Endpoints', () => {
  describe('POST /api/users/signup', () => {
    it('returns 201 and tokens when signup is successful', async () => {
      // 1. Mock DB: Email not found
      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue(null);

      // 2. Mock DB: Return mock user after creation
      (AuthRepository.createUserWithOutbox as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        role: 'CUSTOMER',
      });

      // 3. Mock the helper functions
      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);
      (AuthRepository.saveRefreshToken as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          email: 'test@teleshop.com',
          password: 'Password123!',
        })
        .expect(201); // Expect HTTP Status 201

      // Check the returned data is in the correct format
      expect(response.body.message).toEqual('Signup successful');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user.email).toEqual('test@teleshop.com');
      // Token is set in the Cookie header (session)
      expect(response.get('Set-Cookie')).toBeDefined();
    });

    it('returns 400 if email is already in use', async () => {
      // Mock DB: Email already in use
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
    it('returns 200 with a cookie if signin is successful', async () => {
      const plainPassword = 'Password123!';
      const hashedPassword = await Password.toHash(plainPassword);

      // Mock DB: Find the user and verify the password
      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        password: hashedPassword,
        failedLoginAttempts: 0,
        lockedUntil: null,
      });

      (AuthRepository.createAuditLog as jest.Mock).mockResolvedValue(true);
      (AuthRepository.saveRefreshToken as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/api/auth/signin')
        .send({
          email: 'test@teleshop.com',
          password: plainPassword,
        })
        .expect(200);

      expect(response.body.message).toEqual('Signin successful');
      expect(response.get('Set-Cookie')).toBeDefined();
    });

    it('returns 400 if password is incorrect', async () => {
      const hashedPassword = await Password.toHash('CorrectPassword123!');

      (AuthRepository.findByEmail as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'test@teleshop.com',
        password: hashedPassword,
        failedLoginAttempts: 0,
        lockedUntil: null,
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
