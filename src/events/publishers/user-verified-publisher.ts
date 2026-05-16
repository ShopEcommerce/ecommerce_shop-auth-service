import { BasePublisher, Subjects, UserVerifiedEvent } from '@teleshop/common';

export class UserVerifiedPublisher extends BasePublisher<UserVerifiedEvent> {
  subject: Subjects.UserVerified = Subjects.UserVerified;
}
