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
import { JWTPayloadDTO } from '../dtos/JWTPayloadDTO'
import { LoginEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { BearerTokenProcessor } from '../helpers/BearerTokenProcessor'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { RequestAuthorization } from '../types/LoginTypes'

const metadataKey = AuthorizationLibDefaultOwner + 'JWT_GUARD'

export const JWTGuard = (step: 'ACCESS' | 'REFRESH' = 'ACCESS') => SetMetadata(metadataKey, { step })

@Injectable()
export class AuthenticationJWTGuard implements CanActivate {
  private secondarySecret: string
  private repository: Repository<LoginEntity>
  constructor(private reflector: Reflector, @Inject(JwtService) private readonly jwtService: JwtService) {
    this.secondarySecret = AuthenticationModule.config.secondarySecret
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const params = this.reflector.getAllAndOverride<{ step: string; secret: 'PRIMARY' | 'SECONDARY' }>(metadataKey, [
      context.getHandler(),
      context.getClass(),
    ])

    if (!params) return true

    try {
      const request: RequestAuthorization & { headers: any; processedHeaderDTO: any } = context
        .switchToHttp()
        .getRequest()

      if (request.headers === undefined) throw Error('No header given')
      if (!request.headers['authorization']) throw Error('No authorization header given')
      const [bearer, token] = request.headers['authorization'].split(' ')
      if (bearer !== 'Bearer') throw Error('Invalid bearer token')
      const bearerTokenProcessor = new BearerTokenProcessor<JWTPayloadDTO>(this.jwtService, token)
      if (!bearerTokenProcessor.isBearerToken()) throw Error('JWT decode error')
      if (!bearerTokenProcessor.isSignatureValid(params.secret === 'SECONDARY' ? this.secondarySecret : undefined))
        throw Error('JWT signature error')
      if (params.step !== bearerTokenProcessor.payload?.type) throw Error('Invalid type')

      if (
        request.processedTemporaryPayloadDTO &&
        request.processedTemporaryPayloadDTO.id !== request.processedPayloadDTO.id
      )
        throw Error('User id not math in authorized payload')

      request.processedPayloadDTO = bearerTokenProcessor.payload
      if (request.processedHeaderDTO) {
        request.processedHeaderDTO.userId = bearerTokenProcessor.payload?.id
        request.processedHeaderDTO.expirationTime = bearerTokenProcessor.expirationTime
      }

      const loginEntity = await this.repository.findOne({ where: { id: request.processedPayloadDTO.id } })
      if (loginEntity.validationToken !== request.processedPayloadDTO.validationToken)
        throw Error('Invalid validation token')
      if (loginEntity.passwordToken !== request.processedPayloadDTO.passwordToken) throw Error('Invalid password token')

      return true
    } catch (error) {
      throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
    }
  }
}
