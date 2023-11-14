import { Injectable } from '@nestjs/common'
import { FindManyOptions, Repository } from 'typeorm'
import { LoginLogEntity } from '../entities'
import { AuthenticationModule } from '../module/AuthenticationModule'

@Injectable()
export class LoginLogService {
  private repository: Repository<LoginLogEntity>

  constructor() {
    this.repository = AuthenticationModule.connection.getRepository(LoginLogEntity)
  }

  async create(log: { agent: string; loginId: string; ipAddress: string; eventCode: string; eventMessage: string }) {
    return this.repository.insert(this.repository.create(log))
  }

  async find(options?: FindManyOptions<LoginLogEntity>): Promise<LoginLogEntity[]> {
    return this.repository.find(options)
  }

  async findAndCount(options?: FindManyOptions<LoginLogEntity>): Promise<[LoginLogEntity[], number]> {
    return this.repository.findAndCount(options)
  }
}
