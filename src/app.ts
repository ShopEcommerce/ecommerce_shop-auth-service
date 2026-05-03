import express, { RequestHandler, ErrorRequestHandler } from 'express';
import cookieSession from 'cookie-session';
import cors from 'cors';
import { errorHandler, NotFoundError, correlationId } from '@teleshop/common';
import { authRouter } from './modules/auth/auth.route';

const app = express();

app.set('trust proxy', true);

app.use(
  cors({
    origin: true, 
    credentials: true, 
  })
);

app.use(express.json());

app.use(correlationId as unknown as RequestHandler);

app.use(
  cookieSession({
    signed: false,
    secure: process.env.NODE_ENV === 'production', 
  })
);

app.use('/api/auth', authRouter);

app.all(/.*/, () => {
  throw new NotFoundError();
});

app.use(errorHandler as unknown as ErrorRequestHandler);

export { app };