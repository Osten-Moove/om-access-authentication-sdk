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

export const JWTGuard = (roles: Array<string> = null, step: 'ACCESS' | 'REFRESH' = 'ACCESS') =>
  SetMetadata(metadataKey, { step, roles })

@Injectable()
export class AuthenticationJWTGuard implements CanActivate {
  private secret: string
  private repository: Repository<LoginEntity>
  constructor(private reflector: Reflector, @Inject(JwtService) private readonly jwtService: JwtService) {
    this.secret = AuthenticationModule.config.secret
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
    if(AuthenticationModule.config.debug) console.log(`AuthenticationJWTGuard::constructor.repository: ${this.repository}`)
  }

  async canActivate<T>(context: ExecutionContext): Promise<boolean> {
    const params = this.reflector.getAllAndOverride<{ step: string; roles: Array<string> }>(metadataKey, [
      context.getHandler(),
      context.getClass(),
    ])
    if (AuthenticationModule.config.debug) console.log(`AuthenticationJWTGuard::canActivate.params: ${params}`)
    if (!params) return true

    try {
      const request: RequestAuthorization<T> & { headers: any; processedHeaderDTO: any} = context
        .switchToHttp()
        .getRequest()

      if (request.headers === undefined) throw Error('No header given')
      if (!request.headers['authorization']) throw Error('No authorization header given')
      const [bearer, token] = request.headers['authorization'].split(' ')
      request.userType = request.headers['x-user-type']
      if (request.userType && params.roles && !params.roles.includes(request.userType))
        throw Error('User type not authorized for operation')
      if (bearer !== 'Bearer') throw Error('Invalid bearer token')
      const bearerTokenProcessor = new BearerTokenProcessor<T, JWTPayloadDTO<T>>(this.jwtService, token)
      if (!bearerTokenProcessor.isBearerToken()) throw Error('JWT decode error')
      if (!bearerTokenProcessor.isSignatureValid(this.secret)) throw Error('JWT signature error')
      if (params.step !== bearerTokenProcessor.payload?.type) throw Error('Invalid type')

      if (
        request.processedTemporaryPayloadDTO &&
        request.processedTemporaryPayloadDTO.id !== request.processedPayloadDTO.id
      )
        throw Error('User id not math in authorized payload between access and temporary payload')

      request.processedPayloadDTO = bearerTokenProcessor.payload
      if (request.processedHeaderDTO) {
        request.processedHeaderDTO.userId = bearerTokenProcessor.payload?.id
        request.processedHeaderDTO.expirationTime = bearerTokenProcessor.expirationTime
      }

      const loginEntity = await this.repository.findOne({ where: { id: request.processedPayloadDTO.id } })
      if (loginEntity.validationToken !== request.processedPayloadDTO.validationToken)
        throw Error('Invalid validation token')
      if (loginEntity.passwordToken !== request.processedPayloadDTO.passwordToken) throw Error('Invalid password token')
      if (params.roles && params.roles.length > 0 && !loginEntity.roles.some((it) => params.roles.includes(it)))
        throw Error('User not have role for action')
      return true
    } catch (error) 
      throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
    }
  }
}
