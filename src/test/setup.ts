process.env.JWT_SECRET = 'test-secret-key-for-jest';
process.env.MAX_FAILED_ATTEMPTS = '5';
process.env.LOCK_TIME_MINUTES = '15';
process.env.REFRESH_TOKEN_DAYS = '7';

process.env.DATABASE_URL = 'postgresql://dummy:dummy@localhost:5432/dummy';

jest.mock('@teleshop/common', () => {
  const originalModule = jest.requireActual('@teleshop/common');
  return {
    ...(originalModule as object),
    rabbitmqWrapper: {
      client: {},
      channel: {
        publish: jest.fn(),
        sendToQueue: jest.fn(),
      },
    },
  };
});

beforeEach(() => {
  jest.clearAllMocks();
});
