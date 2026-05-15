import { AuthRepository } from '../modules/auth/auth.repository';
import { UserRegisteredPublisher } from '../events/publishers/user-registered-publisher';
import { UserPasswordResetRequestedPublisher } from '../events/publishers/password-reset-requested-publisher';
import { rabbitmqWrapper, Subjects } from '@teleshop/common';
import pino from 'pino';

const logger = pino();

let isProcessing = false;

export const startOutboxWorker = () => {
  logger.info('[Outbox Worker] Started watching for pending events...');

  setInterval(async () => {
    if (isProcessing) return;

    isProcessing = true;

    try {
      // 1. Scan database to find events with status = PENDING
      const events = await AuthRepository.getPendingOutboxEvents();
      if (events.length === 0) return;

      // 2. Loop through each event and send
      for (const event of events) {
        try {
          const payload = event.payload as any;

          switch (event.subject) {
            case Subjects.UserRegistered:
              await new UserRegisteredPublisher(rabbitmqWrapper.channel).publish(payload);
              break;
            case Subjects.UserPasswordResetRequested:
              await new UserPasswordResetRequestedPublisher(rabbitmqWrapper.channel).publish(payload);
              break;
            default:
              throw new Error(`Unsupported outbox subject: ${event.subject}`);
          }

          // 3. If no error is thrown -> Mark as published
          await AuthRepository.markOutboxEventAsPublished(event.id);
          logger.info(`[Outbox] Event ${event.id} published successfully.`);
        } catch (publishErr: any) {
          // 4. RabbitMQ error (network issues...) -> Mark as FAILED for later review
          await AuthRepository.markOutboxEventAsFailed(
            event.id,
            publishErr.message || 'Unknown error',
          );
          logger.error(`[Outbox] Failed to publish event ${event.id}`);
        }
      }
    } catch (err) {
      logger.error({ err }, '[Outbox Worker] Error querying database');
    } finally {
      isProcessing = false;
    }
  }, 3000);
};
