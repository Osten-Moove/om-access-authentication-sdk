import { Injectable } from '@nestjs/common'
import { ApiKeyLogEntity } from '../entities'
import { AuthenticationModule } from '../module/AuthenticationModule'
import type { FindManyOptions, Repository } from 'typeorm'
import type { RegisterApiKeyLogRequest } from '../types/ApiKeyLogTypes'

@Injectable()
export class ApiKeyLogService {
  private repository: Repository<ApiKeyLogEntity>

  constructor() {
    this.repository = AuthenticationModule.connection.getRepository(ApiKeyLogEntity)
  }

  async register(log: RegisterApiKeyLogRequest) {
    return this.repository.insert(this.repository.create(log))
  }

  async find(options?: FindManyOptions<ApiKeyLogEntity>): Promise<ApiKeyLogEntity[]> {
    return this.repository.find(options)
  }

  async findAndCount(options?: FindManyOptions<ApiKeyLogEntity>): Promise<[ApiKeyLogEntity[], number]> {
    return this.repository.findAndCount(options)
  }
}
