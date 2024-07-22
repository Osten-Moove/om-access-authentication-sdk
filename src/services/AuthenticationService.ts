import { Inject, Injectable } from '@nestjs/common'
import { JwtService, JwtSignOptions } from '@nestjs/jwt'
import * as bcrypt from 'bcrypt'
import { Repository } from 'typeorm'
import { JWTPayloadDTO } from '../dtos/JWTPayloadDTO'
import { JWTTemporaryPayloadDTO } from '../dtos/JWTTemporaryPayloadDTO'
import { LoginEntity } from '../entities'
import { ErrorCode } from '../helpers/ErrorCode'
import { generateNumberString } from '../helpers/GeneratePin'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { GenerateJwtWithPinOptions } from '../types/LoginTypes'
import { LoginLogService } from './LoginLogService'
import { JWTDynamicPayloadDTO } from '../dtos/JWTDynamicPayloadDTO'
import { Logger } from '@duaneoli/logger'

@Injectable()
export class AuthenticationService {
  private repository: Repository<LoginEntity>

  constructor(
    @Inject(JwtService) private readonly jwtService: JwtService,
    @Inject(LoginLogService) private readonly loginLogService: LoginLogService,
  ) {
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::constructor.repository: ${this.repository}`)
  }

  private getLoginForGenerateToken(loginId: string) {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::getLoginForGenerateToken.loginId: ${loginId}`)
    return this.repository.findOne({
      where: { id: loginId },
      select: { id: true, passwordToken: true, validationToken: true, roles: true },
    })
  }

  private generatePrimaryJWT<T>(payload: Partial<JWTPayloadDTO<T>>, expiresIn = '1d') {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::generatePrimaryJWT.payload: ${payload}`)
    const p = JWTPayloadDTO.createPayload(payload)
    const options: JwtSignOptions = { expiresIn }
    return this.jwtService.sign(p, options)
  }

  private generateSecondaryJWT<R>(payload: Partial<JWTTemporaryPayloadDTO<R>>, expiresIn = '1d') {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::generateSecondaryJWT.payload: ${payload}`)
    const p = JWTTemporaryPayloadDTO.createPayload(payload)
    const options: JwtSignOptions = { expiresIn, secret: AuthenticationModule.config.secondarySecret }
    return this.jwtService.sign(p, options)
  }

  async generateDynamicJWT<T>(id: string, type: string, options?: GenerateJwtWithPinOptions, moreInfo?: T) {
    const _options: GenerateJwtWithPinOptions = Object.assign(
      { pinLength: 6, expiresIn: '10m' } as GenerateJwtWithPinOptions,
      options,
    )
    
    const pin = generateNumberString(_options.pinLength)
    const pinHash = bcrypt.hashSync(pin, 10)
    const payload: Partial<JWTDynamicPayloadDTO<T>> = { id, type, pin: pinHash,  moreInfo}

    const token = this.generateSecondaryJWT<T>(payload, _options.expiresIn)

    return { token, pin }
  }

  async generateTemporaryJWT<T>(id: string, type: string, options?: GenerateJwtWithPinOptions, moreInfo?: T) {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::generateTemporaryJWT.id: ${id}, type: ${type}, options: ${options}, moreInfo: ${moreInfo}`)
    const _options: GenerateJwtWithPinOptions = Object.assign(
      { pinLength: 6, expiresIn: '10m' } as GenerateJwtWithPinOptions,
      options,
    )
    
    const pin = generateNumberString(_options.pinLength)
    const login = await this.getLoginForGenerateToken(id)
    const pinHash = bcrypt.hashSync(pin, 10)
    const payload: Partial<JWTTemporaryPayloadDTO<T>> = { id, type, pin: pinHash,  moreInfo, ...login}

    const token = this.generateSecondaryJWT<T>(payload, _options.expiresIn)

    return { token, pin }
  }

  validatePin(validationToken: string, pin: string): boolean {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::validatePin.validationToken: ${validationToken}, pin: ${pin}`)
    return bcrypt.compareSync(pin, validationToken)
  }

  async generateJWTAccess<T>(loginId: string, moreInfo?: T) {
    if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::generateJWTAccess.loginId: ${loginId}, moreInfo: ${moreInfo}`)
    const loginEntity = await this.getLoginForGenerateToken(loginId)

    return {
      access: this.generatePrimaryJWT<T>({ id: loginId, type: 'ACCESS', moreInfo, ...loginEntity}),
      refresh: this.generatePrimaryJWT<T>({ id: loginId, type: 'REFRESH', moreInfo, ...loginEntity }),
    }
  }

  async login(
    login: string,
    password: string,
    options: { agent: string; ipAddress: string },
    role: string,
  ): Promise<[LoginEntity, ErrorCode | undefined]> {
    try {
      if(AuthenticationModule.config.debug) Logger.debug('AuthenticationService::login started')
      const loginEntity = await this.repository.findOneBy({
        login,
      })
      if(AuthenticationModule.config.debug) Logger.debug(`loginEntity: ${loginEntity}`)

      if (!loginEntity) return [null, ErrorCode.LOGIN_NOT_FOUND]
      if (role && !loginEntity.roles.includes(role)) return [null, ErrorCode.LOGIN_ROLE_INVALID]
      if(AuthenticationModule.config.debug) Logger.debug('AuthenticationService::login going to compare password')
      const validPassword = bcrypt.compareSync(password, loginEntity.password)
      if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::login password compared, validPassword: ${validPassword}`)
      if (!validPassword) return [null, ErrorCode.PASSWORD_INVALID]

      this.loginLogService.create({
        ...options,
        loginId: loginEntity.id,
        eventCode: 'LOGIN_SUCCESS',
        eventMessage: 'Login successfully',
      })

      return [loginEntity, null]
    } catch (error) {
      if(AuthenticationModule.config.debug) Logger.debug(`AuthenticationService::login ${error}`)
      return [null, error]
    }
  }
}
