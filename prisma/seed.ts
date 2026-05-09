import { PrismaClient } from '@prisma/client';
import { Password } from '../src/utils/password'; 

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding Auth Service Database...');

  await prisma.auditLog.deleteMany({});
  await prisma.refreshToken.deleteMany({});
  await prisma.passwordResetToken.deleteMany({});
  await prisma.outboxEvent.deleteMany({});
  await prisma.user.deleteMany({});

  const defaultPassword = await Password.toHash('Password123!');

  await prisma.user.create({
    data: {
      email: 'admin@teleshop.com',
      password: defaultPassword,
      role: 'ADMIN',
    },
  });

  await prisma.user.create({
    data: {
      email: 'seller@teleshop.com',
      password: defaultPassword,
      role: 'SELLER',
    },
  });

  await prisma.user.create({
    data: {
      email: 'customer@teleshop.com',
      password: defaultPassword,
      role: 'CUSTOMER',
    },
  });

  console.log('Seeding complete! 3 sample accounts created (admin, seller, customer) with password: Password123!');
}

main()
  .catch((e) => {
    console.error(e);
    throw e;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });