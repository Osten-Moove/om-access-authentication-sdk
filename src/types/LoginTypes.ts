import { JWTPayloadDTO } from '../dtos/JWTPayloadDTO'
import { JWTTemporaryPayloadDTO } from '../dtos/JWTTemporaryPayloadDTO'

export type CreateLogin = {
  id?: string
  login: string
  password?: string
  user: {
    email: string
    fullName: string
  }
}

export type CreateLogins = Array<CreateLogin>

export type GenerateJwtWithPinOptions = {
  pinLength?: number
  expiresIn?: string
}

export type RequestAuthorization = {
  processedPayloadDTO: JWTPayloadDTO
  processedTemporaryPayloadDTO: JWTTemporaryPayloadDTO
  headers: { 'x-temporary-authorization'?: string; 'x-email-pin'?: string; 'x-otp-pin'?: string }
}

export const enum RequiredPin {
  NONE = 'NONE',
  ONLY_EMAIL = 'EMAIL',
  ONLY_OTP = 'OTP',
  ANY = 'ANY',
}

export const enum EventCode {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
}
