import { PrismaClient } from '@prisma/client';
import { Password } from '../src/utils/password';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import * as dotenv from 'dotenv';
import pino from 'pino';

dotenv.config();

const logger = pino();

const connectionString = process.env.DATABASE_URL;
const pool = new Pool({ connectionString });
const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({ adapter });

async function main() {
  logger.info('Seeding Auth Service Database...');

  await prisma.auditLog.deleteMany({});
  await prisma.refreshToken.deleteMany({});
  await prisma.passwordResetToken.deleteMany({});
  await prisma.emailVerificationToken.deleteMany({});
  await prisma.outboxEvent.deleteMany({});
  await prisma.user.deleteMany({});

  const defaultPassword = await Password.toHash('Password123!');

  await prisma.user.create({
    data: {
      id: '00000000-0000-0000-0000-000000000001',
      email: 'admin@teleshop.com',
      password: defaultPassword,
      role: 'ADMIN',
      status: 'ACTIVE',
    },
  });

  await prisma.user.create({
    data: {
      id: '00000000-0000-0000-0000-000000000002',
      email: 'seller@teleshop.com',
      password: defaultPassword,
      role: 'SELLER',
      status: 'ACTIVE',
    },
  });

  await prisma.user.create({
    data: {
      id: '00000000-0000-0000-0000-000000000003',
      email: 'customer@teleshop.com',
      password: defaultPassword,
      role: 'CUSTOMER',
      status: 'ACTIVE',
    },
  });

  logger.info(
    'Seeding complete! 3 sample accounts created (admin, seller, customer) with password: Password123!',
  );
}

main()
  .catch((e) => {
    logger.error(e);
    throw e;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
