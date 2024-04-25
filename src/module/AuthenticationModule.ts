import { DynamicModule, Global, Module } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { JwtModule } from '@nestjs/jwt'
import { DataSource, DataSourceOptions } from 'typeorm'
import { AuthenticationJWTGuard } from '../decorators/JWTGuard'
import { AuthenticationJWTTemporaryGuard } from '../decorators/JWTTemporaryGuard'
import { LoginEntity, LoginLogEntity, ApiKeyEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { AuthenticationDataSource } from '../helpers/DataSource'
import { AuthenticationService } from '../services/AuthenticationService'
import { LoginLogService } from '../services/LoginLogService'
import { LoginService } from '../services/LoginService'
import { DecoratorConfig } from '../types'

@Global()
@Module({})
export class AuthenticationModule {
  static connection: DataSource
  static config: DecoratorConfig
  static forRoot(database: DataSourceOptions, config?: DecoratorConfig): DynamicModule {
    this.config = config
    if (!this.config.secondarySecret) this.config.secondarySecret = this.config.secret + 'secondary'
    const entities = [LoginEntity, LoginLogEntity, ApiKeyEntity]
    const services = [AuthenticationService, LoginLogService, LoginService]
    const jwtGuard = { provide: APP_GUARD, useClass: AuthenticationJWTGuard }
    const jwtTemporaryGuard = { provide: APP_GUARD, useClass: AuthenticationJWTTemporaryGuard }
    const providers = [...services, jwtGuard, jwtTemporaryGuard]
    const imports = [JwtModule.register({ secret: this.config.secret })]
    const exports = [...services, JwtModule]

    this.connection = new AuthenticationDataSource({
      ...database,
      entities,
      name: AuthorizationLibDefaultOwner,
    })

    if (!config.appName) config.appName = 'OM-AUTHENTICATION-LIB'

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
