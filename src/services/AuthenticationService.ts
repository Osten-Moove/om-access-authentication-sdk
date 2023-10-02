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

@Injectable()
export class AuthenticationService {
  private repository: Repository<LoginEntity>

  constructor(
    @Inject(JwtService) private readonly jwtService: JwtService,
    @Inject(LoginLogService) private readonly loginLogService: LoginLogService,
  ) {
    this.repository = AuthenticationModule.connection.getRepository(LoginEntity)
  }

  private getLoginForGenerateToken(loginId: string) {
    return this.repository.findOne({
      where: { id: loginId },
      select: { id: true, passwordToken: true, validationToken: true },
    })
  }

  private generatePrimaryJWT(payload: Partial<JWTPayloadDTO>, expiresIn = '1d') {
    const p = JWTPayloadDTO.createPayload(payload)
    const options: JwtSignOptions = { expiresIn }
    return this.jwtService.sign(p, options)
  }

  private generateSecondaryJWT(payload: Partial<JWTTemporaryPayloadDTO>, expiresIn = '1d') {
    const p = JWTTemporaryPayloadDTO.createPayload(payload)
    const options: JwtSignOptions = { expiresIn, secret: AuthenticationModule.config.secondarySecret }
    return this.jwtService.sign(p, options)
  }

  async generateTemporaryJWT(id: string, type: string, options?: GenerateJwtWithPinOptions) {
    const login = await this.getLoginForGenerateToken(id)
    const _options: GenerateJwtWithPinOptions = Object.assign(
      { pinLength: 6, expiresIn: '10m' } as GenerateJwtWithPinOptions,
      options,
    )
    const pin = generateNumberString(_options.pinLength)
    const pinHash = bcrypt.hashSync(pin, 10)
    const payload: Partial<JWTTemporaryPayloadDTO> = { id, type, pin: pinHash, ...login }

    const token = this.generateSecondaryJWT(payload, _options.expiresIn)

    return { token, pin }
  }

  validatePin(validationToken: string, pin: string): boolean {
    return bcrypt.compareSync(pin, validationToken)
  }

  async generateJWTAccess(loginId: string) {
    const loginEntity = await this.getLoginForGenerateToken(loginId)
    return {
      access: this.generatePrimaryJWT({ id: loginId, type: 'ACCESS', ...loginEntity }),
      refresh: this.generatePrimaryJWT({ id: loginId, type: 'REFRESH', ...loginEntity }),
    }
  }

  async login(
    login: string,
    password: string,
    options: { agent: string; ipAddress: string },
  ): Promise<[LoginEntity, ErrorCode | undefined]> {
    const loginEntity = await this.repository.findOneBy({ login })
    if (!loginEntity) return [null, ErrorCode.LOGIN_NOT_FOUND]

    const validPassword = bcrypt.compareSync(password, loginEntity.password)
    if (!validPassword) return [null, ErrorCode.PASSWORD_INVALID]

    this.loginLogService.create({
      ...options,
      loginId: loginEntity.id,
      eventCode: 'LOGIN_SUCCESS',
      eventMessage: 'Login successfully',
    })

    return [loginEntity, null]
  }
}
