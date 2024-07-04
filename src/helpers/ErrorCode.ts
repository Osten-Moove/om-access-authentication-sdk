export enum ErrorCode {
  LOGIN_ALREADY_HAS_OTP = 'LOGIN_ALREADY_HAS_OTP',
  TOKEN_OTP_INVALID = 'TOKEN_OTP_INVALID',
  LOGIN_NOT_FOUND = 'Login not found.',
  LOGIN_NOT_VALID = 'Login not valid.',
  LOGIN_ROLE_INVALID = 'Login role invalid.',
  LOGIN_ALREADY_USED = 'Login already used.',
  PASSWORD_INVALID = 'Password invalid.',
  API_KEY_ALREADY_EXISTS = 'Api key already exists.',
  API_KEY_NOT_FOUND = 'Api key not found.',
  API_KEY_DEACTIVATED = 'Api key deactivated.',
  PUBLIC_KEY_AND_SECRET_KEY_NOT_GIVEN = 'You must give a public key or a secret key to validate.'
}
