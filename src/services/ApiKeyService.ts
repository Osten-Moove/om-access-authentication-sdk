import { Inject, Injectable } from '@nestjs/common'
import { ErrorCode } from '../helpers/ErrorCode'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { ApiKeyLogService } from './ApiKeyLogService'
import type { Repository } from 'typeorm'
import { ApiKeyEntity } from '../entities/ApiKeyEntity'
import { ApiKeyOptionsRequest, GenerateApiKeyRequest } from '../types/ApiKeyTypes'
import { ApiKeyLogEvents } from '../types/ApiKeyLogTypes'
import { CryptonSecurity } from '../helpers/Crypton'
import { randomUUID } from 'node:crypto'
import { Logger } from '@duaneoli/logger'


@Injectable()
export class ApiKeyService {
  private repository: Repository<ApiKeyEntity>

  constructor(@Inject(ApiKeyLogService) private readonly apiKeyLogService: ApiKeyLogService,
) {
    this.repository = AuthenticationModule.connection.getRepository(ApiKeyEntity)
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::constructor.repository: ${this.repository}`)
  }

  async generate(data: GenerateApiKeyRequest, options?: ApiKeyOptionsRequest): Promise< ApiKeyEntity | [ApiKeyEntity, ErrorCode]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::generate.data: ${data}`)
    const newSecretKey = CryptonSecurity.generateRandom()

    const cryptSecretKey =  CryptonSecurity.encrypt(newSecretKey, process.env.API_GUARD)

    const apiKeyEntity = await this.repository.create({
      ...data,
      roles: !data.roles && ["Company"] ,
      publicKey: randomUUID().replace(/-/g, ''),
      secretKey: cryptSecretKey
    })
    
    const entitySaved = await this.repository.save(apiKeyEntity)
    const { API_KEY_GENERATED } = ApiKeyLogEvents

    this.apiKeyLogService.register({
        eventCode: API_KEY_GENERATED.code,
        eventMessage: API_KEY_GENERATED.message,
        apiKeyId: entitySaved.id,
        ...options
    })

    return {...entitySaved, secretKey:  newSecretKey}
  }

  async regenerate(apiKeyId: string, options?: ApiKeyOptionsRequest ): Promise< ApiKeyEntity | [ApiKeyEntity, ErrorCode]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::regenerate.apiKeyId: ${apiKeyId}`)
    const apiKey = await this.repository.findOne({ where: { id: apiKeyId } })
   
    if (!apiKey) return [null, ErrorCode.API_KEY_NOT_FOUND]

    const newSecretKey = CryptonSecurity.generateRandom()
    
    const cryptSecretKey = CryptonSecurity.encrypt(newSecretKey, process.env.API_GUARD)

    apiKey.secretKey = cryptSecretKey

    const entitySaved = await this.repository.save(apiKey)

    const { API_KEY_REGENERATED } = ApiKeyLogEvents

    this.apiKeyLogService.register({
        eventCode: API_KEY_REGENERATED.code,
        eventMessage: API_KEY_REGENERATED.message,
        apiKeyId,
        ...options
    })

    return {...entitySaved, secretKey:  newSecretKey}
  }

  async activate(apiKeyId: string, options?: ApiKeyOptionsRequest): Promise<[ApiKeyEntity, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::activate.apiKeyId: ${apiKeyId}`)
    const apiKey = await this.repository.findOne({ where: { id: apiKeyId } })
    if (!apiKey) return [null, ErrorCode.API_KEY_NOT_FOUND]

    apiKey.isActive = true

    const entitySaved = await this.repository.save(apiKey)

    const { API_KEY_ACTIVATED } = ApiKeyLogEvents

    this.apiKeyLogService.register({
        eventCode: API_KEY_ACTIVATED.code,
        eventMessage: API_KEY_ACTIVATED.message,
        apiKeyId,
        ...options
    })

    return [entitySaved, null]
  }

  async deactivate(apiKeyId: string, options?: ApiKeyOptionsRequest): Promise<[ApiKeyEntity, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::deactivate.apiKeyId: ${apiKeyId}`)
    const apiKey = await this.repository.findOne({ where: { id: apiKeyId } })
    if (!apiKey) return [null, ErrorCode.API_KEY_NOT_FOUND]

    apiKey.isActive = false

    const entitySaved = await this.repository.save(apiKey)

    const { API_KEY_DEACTIVATED } = ApiKeyLogEvents

    this.apiKeyLogService.register({
        eventCode: API_KEY_DEACTIVATED.code,
        eventMessage: API_KEY_DEACTIVATED.message,
        apiKeyId,
        ...options
    })

    delete entitySaved.secretKey
    delete entitySaved.publicKey
    
    return [entitySaved, null]
  }

  async revoke(apiKeyId: string, options?: ApiKeyOptionsRequest): Promise<[ApiKeyEntity, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::revoke.apiKeyId: ${apiKeyId}`)
    const apiKey = await this.repository.findOne({ where: { id: apiKeyId } })
    if (!apiKey) return [null, ErrorCode.API_KEY_NOT_FOUND]

    await this.apiKeyLogService.deleteLogsByApiKeyId(apiKeyId);
    const removedEntity = await this.repository.remove(apiKey)


 

    return [removedEntity, null]
  }

  async validate(publicKey?: string, secretKey?: string, options?: ApiKeyOptionsRequest): Promise<[ApiKeyEntity, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyService::validate.publicKey: ${publicKey}, secretKey: ${secretKey}`)
    if(!publicKey && !secretKey) return [null,
        ErrorCode.PUBLIC_KEY_AND_SECRET_KEY_NOT_GIVEN]

    const apiKey = await this.repository.findOne({ where: { publicKey, secretKey } })

    if (!apiKey) return [null, ErrorCode.API_KEY_NOT_FOUND]

    if (!apiKey.isActive) return  [null, ErrorCode.API_KEY_DEACTIVATED]

    const { API_KEY_VALIDATED } = ApiKeyLogEvents

    this.apiKeyLogService.register({
        eventCode: API_KEY_VALIDATED.code,
        eventMessage: API_KEY_VALIDATED.message,
        apiKeyId: apiKey.id,
        ...options
    })

    return [apiKey, null]
  }
}