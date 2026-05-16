/**
 * Auth Service Messages Constants
 * Centralized message definitions for consistent error/success responses
 * Sequential numbering: MSG 01, MSG 02, MSG 03...
 */

export enum MessageCode {
  MSG_01 = 'MSG_01',
  MSG_02 = 'MSG_02',
  MSG_03 = 'MSG_03',
  MSG_04 = 'MSG_04',
  MSG_05 = 'MSG_05',
  MSG_06 = 'MSG_06',
  MSG_07 = 'MSG_07',
  MSG_08 = 'MSG_08',
  MSG_09 = 'MSG_09',
  MSG_10 = 'MSG_10',
  MSG_11 = 'MSG_11',
  MSG_12 = 'MSG_12',
  MSG_13 = 'MSG_13',
  MSG_14 = 'MSG_14',
  MSG_15 = 'MSG_15',
  MSG_16 = 'MSG_16',
  MSG_17 = 'MSG_17',
}

export interface MessageDefinition {
  code: MessageCode;
  message: string;
  httpStatus: number;
  category: 'validation' | 'authentication' | 'authorization' | 'conflict' | 'success';
}

export class AuthMessages {
  // Validation Errors (400)
  static readonly MSG_01: MessageDefinition = {
    code: MessageCode.MSG_01,
    message: 'You need to fill in all valid fields',
    httpStatus: 400,
    category: 'validation',
  };

  static readonly MSG_06: MessageDefinition = {
    code: MessageCode.MSG_06,
    message: 'Invalid email format',
    httpStatus: 400,
    category: 'validation',
  };

  static readonly MSG_07: MessageDefinition = {
    code: MessageCode.MSG_07,
    message:
      'Password must contain at least 8 characters, including uppercase, lowercase, number, and special character',
    httpStatus: 400,
    category: 'validation',
  };

  static readonly MSG_09: MessageDefinition = {
    code: MessageCode.MSG_09,
    message: 'Invalid or expired token',
    httpStatus: 400,
    category: 'validation',
  };

  // Authentication Errors (400)
  static readonly MSG_02: MessageDefinition = {
    code: MessageCode.MSG_02,
    message: 'Email or password is incorrect',
    httpStatus: 400,
    category: 'authentication',
  };

  // Authorization Errors (403)
  static readonly MSG_03: MessageDefinition = {
    code: MessageCode.MSG_03,
    message: 'Your account has been locked',
    httpStatus: 403,
    category: 'authorization',
  };

  static readonly MSG_10: MessageDefinition = {
    code: MessageCode.MSG_10,
    message: "You don't have permission to access this resource",
    httpStatus: 403,
    category: 'authorization',
  };

  // Conflict Errors (409)
  static readonly MSG_05: MessageDefinition = {
    code: MessageCode.MSG_05,
    message: 'Email has already been registered',
    httpStatus: 409,
    category: 'conflict',
  };

  static readonly MSG_11: MessageDefinition = {
    code: MessageCode.MSG_11,
    message: 'Phone number has already been registered',
    httpStatus: 409,
    category: 'conflict',
  };

  static readonly MSG_15: MessageDefinition = {
    code: MessageCode.MSG_15,
    message: 'User is already banned',
    httpStatus: 409,
    category: 'conflict',
  };

  // Conflict Errors (400)
  static readonly MSG_14: MessageDefinition = {
    code: MessageCode.MSG_14,
    message: 'Email is already in use',
    httpStatus: 400,
    category: 'conflict',
  };

  // Success Messages (200-201)
  static readonly MSG_04: MessageDefinition = {
    code: MessageCode.MSG_04,
    message: 'Signin successful',
    httpStatus: 200,
    category: 'success',
  };

  static readonly MSG_08: MessageDefinition = {
    code: MessageCode.MSG_08,
    message: 'Signup successful',
    httpStatus: 201,
    category: 'success',
  };

  static readonly MSG_12: MessageDefinition = {
    code: MessageCode.MSG_12,
    message: 'Password has been reset successfully',
    httpStatus: 200,
    category: 'success',
  };

  static readonly MSG_13: MessageDefinition = {
    code: MessageCode.MSG_13,
    message: 'Email verified successfully. You can now log in',
    httpStatus: 200,
    category: 'success',
  };

  static readonly MSG_16: MessageDefinition = {
    code: MessageCode.MSG_16,
    message: 'Signup successful. Please verify your email to activate your account',
    httpStatus: 201,
    category: 'success',
  };

  static readonly MSG_17: MessageDefinition = {
    code: MessageCode.MSG_17,
    message: 'Please verify your email before signing in',
    httpStatus: 403,
    category: 'authorization',
  };

  /**
   * Get message by code
   */
  static getByCode(code: MessageCode): MessageDefinition {
    // Fallback map. Some legacy codes are aliases and may not be explicitly defined.
    const messages: Partial<Record<MessageCode, MessageDefinition>> = {
      [MessageCode.MSG_01]: this.MSG_01,
      [MessageCode.MSG_02]: this.MSG_02,
      [MessageCode.MSG_03]: this.MSG_03,
      [MessageCode.MSG_04]: this.MSG_04,
      [MessageCode.MSG_05]: this.MSG_05,
      [MessageCode.MSG_06]: this.MSG_06,
      [MessageCode.MSG_07]: this.MSG_07,
      [MessageCode.MSG_08]: this.MSG_08,
      [MessageCode.MSG_09]: this.MSG_09,
      [MessageCode.MSG_10]: this.MSG_10,
      [MessageCode.MSG_11]: this.MSG_11,
      [MessageCode.MSG_12]: this.MSG_12,
      [MessageCode.MSG_13]: this.MSG_13,
      [MessageCode.MSG_14]: this.MSG_14,
      [MessageCode.MSG_15]: this.MSG_15,
      [MessageCode.MSG_16]: this.MSG_16,
      [MessageCode.MSG_17]: this.MSG_17,
    };
    return messages[code] || this.MSG_01;
  }

  /**
   * Build standardized API response
   */
  static buildResponse(success: boolean, message: MessageDefinition, data: any = null) {
    return {
      success,
      message: message.message,
      code: message.code,
      data,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Build error response
   */
  static buildErrorResponse(message: MessageDefinition) {
    return {
      success: false,
      message: message.message,
      code: message.code,
      data: null,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Build success response
   */
  static buildSuccessResponse(message: MessageDefinition, data: any = null) {
    return {
      success: true,
      message: message.message,
      code: message.code,
      data,
      timestamp: new Date().toISOString(),
    };
  }
}

/**
 * Message validation helper
 */
export class MessageValidator {
  static validateEmail(email: string): MessageDefinition | null {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return AuthMessages.MSG_06;
    }
    return null;
  }

  static validatePassword(password: string): MessageDefinition | null {
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!])[A-Za-z\d@#$%^&+=!]{8,}$/;
    if (!passwordRegex.test(password)) {
      return AuthMessages.MSG_07;
    }
    return null;
  }

  static validateRequiredFields(fields: Record<string, any>): MessageDefinition | null {
    for (const [_key, value] of Object.entries(fields)) {
      if (value === null || value === undefined || value === '') {
        return AuthMessages.MSG_01;
      }
    }
    return null;
  }
}
