import { Logger } from '@duaneoli/logger'
import { Injectable } from '@nestjs/common'
import { FindManyOptions, Repository } from 'typeorm'
import { LoginLogEntity } from '../entities'
import { AuthenticationModule } from '../module/AuthenticationModule'

@Injectable()
export class LoginLogService {
  private repository: Repository<LoginLogEntity>

  constructor() {
    this.repository = AuthenticationModule.connection.getRepository(LoginLogEntity)
    if (AuthenticationModule.config.debug) Logger.debug(`LoginLogService::constructor.repository: ${this.repository}`)
  }

  async create(log: { agent: string; loginId: string; ipAddress: string; eventCode: string; eventMessage: string }) {
    if (AuthenticationModule.config.debug) Logger.debug(`LoginLogService::create.log: ${log}`)
    return this.repository.insert(this.repository.create(log))
  }

  async find(options?: FindManyOptions<LoginLogEntity>): Promise<LoginLogEntity[]> {
    if (AuthenticationModule.config.debug) Logger.debug(`LoginLogService::find.options: ${options}`)
    return this.repository.find(options)
  }

  async findAndCount(options?: FindManyOptions<LoginLogEntity>): Promise<[LoginLogEntity[], number]> {
    if (AuthenticationModule.config.debug) Logger.debug(`LoginLogService::findAndCount.options: ${options}`)
    return this.repository.findAndCount(options)
  }

  async deleteOldLogs() {
    return this.repository.query(`DELETE FROM auth.login_logs
                            WHERE id IN (
                                SELECT id
                                FROM (
                                    SELECT id,
                                          ROW_NUMBER() OVER (PARTITION BY login_id ORDER BY created_at DESC) AS rn
                                    FROM auth.login_logs
                                ) AS sub
                                WHERE rn > 10
                            );`)
  }
}
