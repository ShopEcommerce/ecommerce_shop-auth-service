import { BasePublisher, Subjects, UserRegisteredEvent } from '@teleshop/common';

export class UserRegisteredPublisher extends BasePublisher<UserRegisteredEvent> {
  subject: Subjects.UserRegistered = Subjects.UserRegistered;
}