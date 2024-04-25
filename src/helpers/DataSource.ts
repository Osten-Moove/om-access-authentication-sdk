import { DataSource, DataSourceOptions } from 'typeorm'
import { LoginEntity, LoginLogEntity, ApiKeyEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'

export class AuthenticationDataSource extends DataSource {
  constructor(database: DataSourceOptions) {
    super({
      ...database,
      entities: [LoginEntity, LoginLogEntity, ApiKeyEntity],
      name: AuthorizationLibDefaultOwner,
    })
  }
}
