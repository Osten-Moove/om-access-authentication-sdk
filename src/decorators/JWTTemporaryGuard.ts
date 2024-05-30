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
import { Repository } from 'typeorm'
import { JWTTemporaryPayloadDTO } from '../dtos/JWTTemporaryPayloadDTO'
import { LoginEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { BearerTokenProcessor } from '../helpers/BearerTokenProcessor'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { AuthenticationService } from '../services/AuthenticationService'
import { RequestAuthorization, RequiredPin } from '../types/LoginTypes'
import { OtpService } from '../services/OtpService'

const metadataKey = AuthorizationLibDefaultOwner + 'JWT_TEMPORARY_GUARD'

export const JWTTemporaryGuard = (step: string, requiredPin: RequiredPin = RequiredPin.ANY) =>
  SetMetadata(metadataKey, { step, requiredPin })

@Injectable()
export class AuthenticationJWTTemporaryGuard implements CanActivate {
  private secondarySecret: string
  private repository: Repository<LoginEntity>
  constructor(
    private reflector: Reflector,
    @Inject(JwtService) private readonly jwtService: JwtService,
    private readonly authService: AuthenticationService,
    private readonly otpService: OtpService,
  ) {
    this.secondarySecret = AuthenticationModule.config.secondarySecret
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
  }

  private async validateOtpToken(loginId: string, otp: string) {
    const [tokenIsValid] = await this.otpService.validateOTP(loginId, otp)
    if (!tokenIsValid) throw Error('Invalid otp pin')

    return true
  }

  private async validateEmailToken(pin: string, plainPin: string) {
    const pinIsValid = this.authService.validatePin(pin, plainPin)
    if (!pinIsValid) throw Error('Invalid email pin')

    return true
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const params = this.reflector.getAllAndOverride<{ step: string; requiredPin: RequiredPin }>(metadataKey, [
      context.getHandler(),
      context.getClass(),
    ])

    if (!params) return true

    try {
      const request: RequestAuthorization & { processedHeaderDTO: any } = context.switchToHttp().getRequest()

      if (request.headers === undefined) throw Error('No header given')
      if (!request.headers['x-temporary-authorization']) throw Error('No authorization header given')
      const token = request.headers['x-temporary-authorization']
      const bearerTokenProcessor = new BearerTokenProcessor<JWTTemporaryPayloadDTO>(this.jwtService, token)
      if (!bearerTokenProcessor.isBearerToken()) throw Error('JWT decode error')
      if (!bearerTokenProcessor.isSignatureValid(this.secondarySecret)) throw Error('JWT signature error')
      if (params.step !== bearerTokenProcessor.payload?.type) throw Error('Invalid step')

      request.processedTemporaryPayloadDTO = bearerTokenProcessor.payload
      if (request.processedPayloadDTO && request.processedPayloadDTO.id !== request.processedTemporaryPayloadDTO.id)
        throw Error('User id not math in authorized payload')

      if (request.processedHeaderDTO) {
        request.processedHeaderDTO.userId = bearerTokenProcessor.payload?.id
        request.processedHeaderDTO.expirationTime = bearerTokenProcessor.expirationTime
      }

      const pin = request.headers['x-email-pin']
      const otp = request.headers['x-otp-pin']

      switch (params.requiredPin) {
        case RequiredPin.ONLY_EMAIL:
          if (!pin) throw Error('No email pin given')
          await this.validateEmailToken(request.processedTemporaryPayloadDTO.pin, pin)
          break
        case RequiredPin.ONLY_OTP:
          if (!otp) throw Error('No otp pin given')
          await this.validateOtpToken(request.processedTemporaryPayloadDTO.id, otp)
          break
        case RequiredPin.ANY:
          if (!pin && !otp) throw Error('No pin specified')
          if (pin) await this.validateEmailToken(request.processedTemporaryPayloadDTO.pin, pin)
          if (otp) await this.validateOtpToken(request.processedTemporaryPayloadDTO.id, otp)
          break
        default:
          break
      }

      const loginEntity = await this.repository.findOne({ where: { id: request.processedTemporaryPayloadDTO.id } })
      if (loginEntity.validationToken !== request.processedTemporaryPayloadDTO.validationToken)
        throw Error('Invalid validation token')
      if (loginEntity.passwordToken !== request.processedTemporaryPayloadDTO.passwordToken)
        throw Error('Invalid password token')
      return true
    } catch (error) {
      throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
    }
  }
}
