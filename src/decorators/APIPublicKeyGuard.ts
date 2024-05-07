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
import { ApiKeyService } from '../services/ApiKeyService'
import { ApiKeyLogService } from '../services/ApiKeyLogService'
import { ApiKeyLogEvents } from '../types/ApiKeyLogTypes'
import { ErrorMessage } from '../helpers/ErrorCode'

const metadataKey = AuthorizationLibDefaultOwner + 'API_PUBLIC_KEY_GUARD'

export const APIPublicKeyGuard = (scope: string, roles: Array<string> = null) => SetMetadata(metadataKey, { scope, roles })

@Injectable()
export class AuthenticationAPIPublicKeyGuard implements CanActivate {
    constructor(private reflector: Reflector,
        @Inject(ApiKeyService) private readonly apiKeyService: ApiKeyService,
        @Inject(ApiKeyLogService) private readonly apiKeyLogService: ApiKeyLogService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const params = this.reflector.getAllAndOverride<{ scope: string; roles: Array<string> }>(metadataKey, [
            context.getHandler(),
            context.getClass(),
        ])

        if (!params) return true

        try {
            const request: RequestAuthorization & { headers: Record<string, never> } = context
                .switchToHttp()
                .getRequest()

            if (request.headers === undefined) throw Error('No header given')

            if (!request.headers['x-public-key']) throw Error('No "x-public-key" header given')

            request.userType = request.headers['x-user-type']

            if (request.userType && params.roles && !params.roles.includes(request.userType))
                throw Error('User type not authorized for operation')

            const publicKey: string = request.headers['x-public-key']

            const [apiKey, errorValidateApiKey] = await this.apiKeyService.validate(publicKey, null, {
                agent: request.userType,
                eventScope: params.scope
            })

            if (errorValidateApiKey) throw new Error(ErrorMessage[errorValidateApiKey])

            if (params.roles && params.roles.length > 0 && !apiKey.roles.some((role) => params.roles.includes(role)))
                throw Error('Key not have role for action')

            const { API_KEY_USED } = ApiKeyLogEvents

            await this.apiKeyLogService.register({
                eventCode: API_KEY_USED.code,
                eventMessage: API_KEY_USED.message,
                eventScope: params.scope,
                apiKeyId: apiKey.id,
                agent: request.userType,
            })

            return true
        } catch (error) {
            console.log(error)
            throw new HttpException('Not authorized for perform action', HttpStatus.UNAUTHORIZED, { cause: error.message })
        }
    }
}
