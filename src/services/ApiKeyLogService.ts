import { Injectable } from '@nestjs/common'
import { AuthenticationModule } from '../module/AuthenticationModule'
import type { FindManyOptions, Repository } from 'typeorm'
import { ApiKeyLogEntity } from '../entities/ApiKeyLogEntity'
import { RegisterApiKeyLogRequest } from '../types/ApiKeyLogTypes'
import { Logger } from '@duaneoli/logger'

@Injectable()
export class ApiKeyLogService {
  private repository: Repository<ApiKeyLogEntity>

  constructor() {
    this.repository = AuthenticationModule.connection.getRepository(ApiKeyLogEntity)
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyLogService::constructor.repository: ${this.repository}`)
  }

  async register(log: RegisterApiKeyLogRequest) {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyLogService::register.log: ${log}`)
    return this.repository.insert(this.repository.create(log))
  }

  async find(options?: FindManyOptions<ApiKeyLogEntity>): Promise<ApiKeyLogEntity[]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyLogService::find.options: ${options}`)
    return this.repository.find(options)
  }

  async findAndCount(options?: FindManyOptions<ApiKeyLogEntity>): Promise<[ApiKeyLogEntity[], number]> {
    if(AuthenticationModule.config.debug) Logger.debug(`ApiKeyLogService::findAndCount.options: ${options}`)
    return this.repository.findAndCount(options)
  }
}