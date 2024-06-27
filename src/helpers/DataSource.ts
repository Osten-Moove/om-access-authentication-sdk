import { DataSource, DataSourceOptions } from 'typeorm'
import { LoginEntity, LoginLogEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'
import { ApiKeyEntity } from '../entities/ApiKeyEntity'
import { ApiKeyLogEntity } from '../entities/ApiKeyLogEntity'

export class AuthenticationDataSource extends DataSource {
  constructor(database: DataSourceOptions) {
    super({
      ...database,
      entities: [LoginEntity, LoginLogEntity, ApiKeyEntity, ApiKeyLogEntity],
      name: AuthorizationLibDefaultOwner,
    })
  }
}
