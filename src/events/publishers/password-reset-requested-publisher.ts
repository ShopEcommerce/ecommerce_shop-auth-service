import { BasePublisher, Subjects, UserPasswordResetRequestedEvent } from '@teleshop/common';

export class UserPasswordResetRequestedPublisher extends BasePublisher<UserPasswordResetRequestedEvent> {
  subject: Subjects.UserPasswordResetRequested = Subjects.UserPasswordResetRequested;
}
