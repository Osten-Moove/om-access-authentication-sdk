import { Inject, Injectable } from '@nestjs/common'
import * as bcrypt from 'bcrypt'
import { authenticator } from 'otplib'
import { FindManyOptions, FindOneOptions, In, Repository } from 'typeorm'
import { v4 } from 'uuid'
import { LoginEntity } from '../entities'
import { ErrorCode } from '../helpers/ErrorCode'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { CreateLogins, UpdateLogins } from '../types/LoginTypes'
import { LoginLogService } from './LoginLogService'
import { Logger } from '@duaneoli/logger'

@Injectable()
export class LoginService {
  private repository: Repository<LoginEntity>

  constructor(@Inject(LoginLogService) private readonly loginLogService: LoginLogService) {
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::constructor.repository: ${this.repository}`)
  }

  async create(data: CreateLogins): Promise<[Array<LoginEntity>, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::create.data: ${data}`)
    const logins = data.map((it) => it.login)
    const loginInDatabase = await this.repository.find({ where: { login: In(logins) } })
    if (loginInDatabase.length > 0) return [null, ErrorCode.LOGIN_ALREADY_USED]

    const loginEntities = this.repository.create(data)
    const saveEntities = await this.repository.save(loginEntities)
    return [saveEntities, null]
  }

  async update(data: UpdateLogins): Promise<[Array<LoginEntity>, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::update.data: ${data}`)
    const loginIds = data.map((it) => it.id)
    const loginsToUpdate = await this.repository.find({ where: { id: In(loginIds) } })

    if (loginsToUpdate.length !== data.length) return [null, ErrorCode.LOGIN_NOT_FOUND]

    const loginsToUpdateNewData = loginsToUpdate.map((it) => {
      const newData = data.find((data) => data.id === it.id)
      return Object.assign(it, newData)
    })

    const saveEntities = await this.repository.save(loginsToUpdateNewData)
    return [saveEntities, null]
  }

  async remove(loginIds: Array<string>): Promise<[Array<LoginEntity>, ErrorCode | undefined]> {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::remove.loginIds: ${loginIds}`)
    const logins = await this.repository.find({ where: { id: In(loginIds) } })
    if (logins.length !== loginIds.length) return [null, ErrorCode.LOGIN_NOT_FOUND]

    const removeEntities = await this.repository.remove(logins)
    return [removeEntities, null]
  }

  async definedPassword(loginId: string, password: string) {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::definedPassword.loginId: ${loginId}`)
    const loginEntity = await this.repository.findOne({ where: { id: loginId } })
    if (!loginEntity) throw new Error('Login entity not found')

    loginEntity.password = bcrypt.hashSync(password, 10)
    loginEntity.passwordToken = v4()
    loginEntity.validationToken = v4()

    await this.repository.save(loginEntity)
  }

  async changePassword(loginId: string, password: string, options: { agent: string; ipAddress: string }) {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::changePassword.loginId: ${loginId}, options: ${options}`)
    const loginEntity = await this.repository.findOne({ where: { id: loginId } })
    if (!loginEntity) throw new Error('Login entity not found')

    loginEntity.password = bcrypt.hashSync(password, 10)
    loginEntity.passwordToken = v4()
    loginEntity.validationToken = v4()

    await this.repository.save(loginEntity)
    this.loginLogService.create({
      eventCode: 'RECOVERY_CHANGE',
      eventMessage: 'Recovery process finalized',
      loginId: loginEntity.id,
      ...options,
    })
  }

  async invalidateToken(loginId: string) {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::invalidateToken.loginId: ${loginId}`)
    const loginEntity = await this.repository.findOne({ where: { id: loginId } })
    if (!loginEntity) throw new Error('Login entity not found')

    loginEntity.validationToken = v4()
    await this.repository.save(loginEntity)
  }

  async findOne(options: FindOneOptions<LoginEntity>) {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::findOne.options: ${options}`)
    return this.repository.findOne(options)
  }

  async find(options: FindManyOptions<LoginEntity>) {
    if(AuthenticationModule.config.debug) Logger.debug(`LoginService::find.options: ${options}`)
    return this.repository.find(options)
  }
}
