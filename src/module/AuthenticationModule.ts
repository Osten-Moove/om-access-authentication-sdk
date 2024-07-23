import { DynamicModule, Global, Module } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { JwtModule } from '@nestjs/jwt'
import { DataSource, DataSourceOptions } from 'typeorm'
import { AuthenticationJWTGuard } from '../decorators/JWTGuard'
import { AuthenticationJWTTemporaryGuard } from '../decorators/JWTTemporaryGuard'
import { LoginEntity, LoginLogEntity, } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { AuthenticationDataSource } from '../helpers/DataSource'
import { AuthenticationService } from '../services/AuthenticationService'
import { LoginLogService } from '../services/LoginLogService'
import { LoginService } from '../services/LoginService'
import { DecoratorConfig } from '../types'
import { OtpService } from '../services/OtpService'
import { ApiKeyLogService } from '../services/ApiKeyLogService'
import { ApiKeyService } from '../services/ApiKeyService'
import { AuthenticationAPIGuard } from '../decorators/APIGuard'
import { ApiKeyEntity } from '../entities/ApiKeyEntity'
import { ApiKeyLogEntity } from '../entities/ApiKeyLogEntity'
import { AuthenticationJWTDynamicGuard } from '../decorators/JWTDynamicGuard'
import { Logger } from '@duaneoli/logger'

@Global()
@Module({})
export class AuthenticationModule {
  static connection: DataSource
  static config: DecoratorConfig
  static forRoot(database: DataSourceOptions, config?: DecoratorConfig): DynamicModule {
    this.config = config
    if (!this.config.secondarySecret) this.config.secondarySecret = this.config.secret + 'secondary'
    const entities = [LoginEntity, LoginLogEntity, ApiKeyEntity, ApiKeyLogEntity]
    const services = [AuthenticationService, LoginLogService, LoginService, OtpService,ApiKeyLogService, ApiKeyService]
    const apiKeyGuard = { provide: APP_GUARD, useClass: AuthenticationAPIGuard }

    const jwtGuard = { provide: APP_GUARD, useClass: AuthenticationJWTGuard }
    const jwtTemporaryGuard = { provide: APP_GUARD, useClass: AuthenticationJWTTemporaryGuard }
    const jwtDynamicGuard = { provide: APP_GUARD, useClass: AuthenticationJWTDynamicGuard }
    const providers = [...services, jwtGuard, jwtTemporaryGuard, apiKeyGuard, jwtDynamicGuard]
    const imports = [JwtModule.register({ secret: this.config.secret })]
    const exports = [...services, JwtModule]

    this.connection = new AuthenticationDataSource({
      ...database,
      entities,
      name: AuthorizationLibDefaultOwner,
    })

    if (!this.config.appName) this.config.appName = 'OM-AUTHENTICATION-LIB'
    if (this.config.debug) Logger.debug('AuthenticationModule Inicialized') 

    return {
      global: true,
      module: AuthenticationModule,
      imports,
      providers,
      exports,
    }
  }

  async onModuleInit() {
    await AuthenticationModule.connection.initialize()
  }

  async onModuleDestroy() {
    await AuthenticationModule.connection.destroy()
  }
}
