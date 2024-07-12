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
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { RequestAuthorization } from '../types/LoginTypes'
import { ErrorCode } from '../helpers/ErrorCode'
import { ApiKeyService } from '../services/ApiKeyService'
import { JwtService } from '@nestjs/jwt'
import { BearerTokenProcessor } from '../helpers/BearerTokenProcessor'
import { Repository } from 'typeorm'
import { ApiKeyEntity } from '../entities/ApiKeyEntity'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { CryptonSecurity } from '../helpers/Crypton'
import { ApiKeyLogEvents } from '../types/ApiKeyLogTypes'
import { ApiKeyLogService } from '../services/ApiKeyLogService'
import { warn } from 'console'
import { JWTApiPayloadDTO } from '../dtos/JWTApiPayloadDTO'

const metadataKey = AuthorizationLibDefaultOwner + 'API_KEY_GUARD'


export const APIGuard = (scope: string, roles: Array<string> = ["Company"]) => SetMetadata(metadataKey, { scope, roles })

@Injectable()
export class AuthenticationAPIGuard implements CanActivate {
    private repository: Repository<ApiKeyEntity>

    constructor(private reflector: Reflector,
        @Inject(ApiKeyService) private readonly apiKeyService: ApiKeyService,
        @Inject(JwtService) private readonly jwtService: JwtService,
        @Inject(ApiKeyLogService) private readonly apiKeyLogService: ApiKeyLogService
        
    ) {
        this.repository = AuthenticationModule.connection.getRepository(ApiKeyEntity)
    }

    async canActivate<T>(context: ExecutionContext): Promise<boolean> {
        const params = this.reflector.getAllAndOverride<{ scope: string; roles: Array<string> }>(metadataKey, [
            context.getHandler(),
            context.getClass(),
    ])

        if (!params) return true

        try {
            const request: RequestAuthorization<T> & { headers: any } = context
            .switchToHttp()
            .getRequest()

            if (request.headers === undefined) throw Error('No header given')
            if (!request.headers['authorization']) throw Error('No authorization header given')
            const [bearer, token] = request.headers['authorization'].split(' ')
        
            request.userType = request.headers['x-user-type']

            if (request.userType && params.roles && !params.roles.includes(request.userType)) throw Error('User type not authorized for operation')
            if (bearer !== 'Bearer') throw Error('Invalid bearer token')
            const bearerTokenProcessor = new BearerTokenProcessor<T, JWTApiPayloadDTO<T>>(this.jwtService, token)
            if (!bearerTokenProcessor.isBearerToken()) throw Error('JWT decode error')
            
            const  { publicKey, ...props }  = this.jwtService.decode(token) as { publicKey: string, moreInfo: T}
            
            const [apiKey, errorValidateApiKey] = await this.apiKeyService.validate(publicKey ,null, {
                agent: "mudar",
                eventScope: params.scope,
            })

            
            if (errorValidateApiKey) throw new Error(ErrorCode[errorValidateApiKey])

            const encryptedSecretKey = CryptonSecurity.decrypt(apiKey.secretKey, process.env.API_GUARD)
            
            if (!bearerTokenProcessor.isSignatureValid(encryptedSecretKey)){

                const { API_KEY_SECRET_KEY } = ApiKeyLogEvents

                this.apiKeyLogService.register({
                    eventCode: API_KEY_SECRET_KEY.code,
                    eventMessage: API_KEY_SECRET_KEY.message,
                    eventScope: params.scope,
                    apiKeyId: apiKey.id,
                    agent: request.userType,
                })
                
                throw warn("The JWT is not valid. Please create the JWT with the correct secret key.")
            }
            request.processedApiPayloadDTO = { 
                alias: apiKey.alias,
                isActive: apiKey.isActive,
                roles: apiKey.roles,
                id: apiKey.id,
                moreInfo: {
                    ...props.moreInfo
                }
            }

            if (params.roles && params.roles.length > 0 && !apiKey.roles.some((role) => params.roles.includes(role)))
                throw Error('Key not have role for action')

            return true
        } catch (error) {
            console.log(error)
            throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
        }
    }
}