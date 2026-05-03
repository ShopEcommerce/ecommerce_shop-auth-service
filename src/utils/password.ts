import bcrypt from 'bcryptjs';

export class Password {
  static async toHash(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  static async compare(
    storedPassword: string,
    suppliedPassword: string
  ): Promise<boolean> {
    return bcrypt.compare(suppliedPassword, storedPassword);
  }
}