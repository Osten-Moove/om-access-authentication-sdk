import { JwtService } from '@nestjs/jwt'
import { JWTPayloadDTO } from '../dtos/JWTPayloadDTO'
import { JWTTemporaryPayloadDTO } from '../dtos/JWTTemporaryPayloadDTO'
import { JWTApiPayloadDTO } from '../dtos/JWTApiPayloadDTO'

export class BearerTokenProcessor<R,T = JWTPayloadDTO<R> | JWTTemporaryPayloadDTO<R> | JWTApiPayloadDTO<R>>  {
  private jwtService: JwtService
  token: string = ''
  payload?: T
  expirationTime?: number
  creationTime?: string

  constructor(jwtService: JwtService, token?: string) {
    this.jwtService = jwtService
    if (token) this.token = token

  }

  isBearerToken(): boolean {
    return this.jwtService.decode(this.token) ? true : false
  }

  isSignatureValid(secret?: string): boolean {
    const bearerTokenProcessor = this.jwtService.verify(this.token, secret ? { secret } : undefined)
    this.payload = bearerTokenProcessor.payload
    this.expirationTime = bearerTokenProcessor.exp
    this.creationTime = bearerTokenProcessor.jti

    return true
  }

  matchesPayload(): boolean {
    return !!this.payload && JWTPayloadDTO.matchesObject(this.payload)
  }

  create(payload: JWTPayloadDTO<R>, expirationTime: string = '1d'): string {
    const options = expirationTime ? { expiresIn: expirationTime } : undefined
    return this.jwtService.sign({ payload }, options)
  }
}
