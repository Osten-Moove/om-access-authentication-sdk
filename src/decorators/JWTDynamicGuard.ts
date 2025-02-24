import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  SetMetadata,
} from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import { JWTDynamicPayloadDTO } from '../dtos/JWTDynamicPayloadDTO'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { BearerTokenProcessor } from '../helpers/BearerTokenProcessor'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { AuthenticationService } from '../services/AuthenticationService'
import { RequestAuthorization, RequiredPin } from '../types/LoginTypes'

const metadataKey = AuthorizationLibDefaultOwner + 'JWT_DYNAMIC_GUARD'

export const JWTDynamicGuard = (step: string, requiredPin: RequiredPin = RequiredPin.ANY, ignoreExpiration?: boolean) =>
  SetMetadata(metadataKey, { step, requiredPin })

@Injectable()
export class AuthenticationJWTDynamicGuard implements CanActivate {
  private secondarySecret: string
  constructor(
    private reflector: Reflector,
    @Inject(JwtService) private readonly jwtService: JwtService,
    private readonly authService: AuthenticationService,
  ) {
    this.secondarySecret = AuthenticationModule.config.secondarySecret
  }

  private async validateEmailToken(pin: string, plainPin: string) {
    const pinIsValid = this.authService.validatePin(pin, plainPin)
    if (!pinIsValid) throw Error('Invalid email pin')

    return true
  }

  async canActivate<T>(context: ExecutionContext): Promise<boolean> {
    const params = this.reflector.getAllAndOverride<{
      step: string
      requiredPin: RequiredPin
      ignoreExpiration?: boolean
    }>(metadataKey, [context.getHandler(), context.getClass()])

    if (!params) return true

    try {
      const request: RequestAuthorization<T> & { processedHeaderDTO: any } = context.switchToHttp().getRequest()

      if (request.headers === undefined) throw Error('No header given')
      if (!request.headers['x-dynamic-authorization']) throw Error('No authorization header given')

      const token = request.headers['x-dynamic-authorization']

      const bearerTokenProcessor = new BearerTokenProcessor<T, JWTDynamicPayloadDTO<T>>(this.jwtService, token)

      if (!bearerTokenProcessor.isBearerToken()) throw Error('JWT decode error')
      if (!bearerTokenProcessor.isSignatureValid(this.secondarySecret, params.ignoreExpiration))
        throw Error('JWT signature error')
      if (params.step !== bearerTokenProcessor.payload?.type) throw Error('Invalid step')

      request.processedDynamicPayloadDTO = bearerTokenProcessor.payload

      const pin = request.headers['x-email-pin']

      switch (params.requiredPin) {
        case RequiredPin.ONLY_EMAIL:
          if (!pin) throw Error('No email pin given')
          await this.validateEmailToken(request.processedDynamicPayloadDTO.pin, pin)
          break
        case RequiredPin.ANY:
          if (!pin) throw Error('No pin specified')
          if (pin) await this.validateEmailToken(request.processedDynamicPayloadDTO.pin, pin)
          break
        default:
          break
      }

      return true
    } catch (error) {
      throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
    }
  }
}
