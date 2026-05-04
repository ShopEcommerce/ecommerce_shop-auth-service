import { AuthRepository } from '../modules/auth/auth.repository';
import { UserRegisteredPublisher } from '../events/publishers/user-registered-publisher';
import { rabbitmqWrapper, Subjects } from '@teleshop/common';
import pino from 'pino';

const logger = pino();

export const startOutboxWorker = () => {
  logger.info('[Outbox Worker] Started watching for pending events...');
  
  setInterval(async () => {
    try {
      // 1. Scan database to find events with status = PENDING
      const events = await AuthRepository.getPendingOutboxEvents();
      if (events.length === 0) return;

      // 2. Loop through each event and send
      for (const event of events) {
        try {
          if (event.subject === Subjects.UserRegistered) {

            const payload = event.payload as any;
            await new UserRegisteredPublisher(rabbitmqWrapper.channel).publish(payload);
          }
          
          // 3. If no error is thrown -> Mark as published
          await AuthRepository.markOutboxEventAsPublished(event.id);
          logger.info(`[Outbox] Event ${event.id} published successfully.`);
          
        } catch (publishErr: any) {
          // 4. RabbitMQ error (network issues...) -> Mark as FAILED for later review
          await AuthRepository.markOutboxEventAsFailed(event.id, publishErr.message || 'Unknown error');
          logger.error(`[Outbox] Failed to publish event ${event.id}`);
        }
      }
    } catch (err) {
      logger.error('[Outbox Worker] Error querying database');
    }
  }, 3000);
};