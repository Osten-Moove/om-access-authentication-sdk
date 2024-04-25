export enum ErrorCode {
  LOGIN_NOT_FOUND = 'LOGIN_NOT_FOUND',
  LOGIN_NOT_VALID = 'LOGIN_NOT_VALID',
  LOGIN_ROLE_INVALID = 'LOGIN_ROLE_INVALID',
  LOGIN_ALREADY_USED = 'LOGIN_ALREADY_USED',
  PASSWORD_INVALID = 'PASSWORD_INVALID',

  API_KEY_NOT_FOUND = 'API_KEY_NOT_FOUND',
  API_KEY_DEACTIVATED = 'API_KEY_DEACTIVATED',
  PUBLIC_KEY_AND_SECRET_KEY_NOT_GIVEN = 'PUBLIC_KEY_AND_SECRET_KEY_NOT_GIVEN'
}

export const ErrorMessage: Record<ErrorCode, string> = {
    LOGIN_NOT_FOUND: 'Login not found.',
    LOGIN_NOT_VALID: 'Login not valid.',
    LOGIN_ROLE_INVALID: 'Login role invalid.',
    LOGIN_ALREADY_USED: 'Login already used.',
    PASSWORD_INVALID: 'Password invalid.',

    API_KEY_NOT_FOUND: 'Api key not found.',
    API_KEY_DEACTIVATED: 'Api key deactivated.',
    PUBLIC_KEY_AND_SECRET_KEY_NOT_GIVEN: 'You must give a public key or a secret key to validate.'
}