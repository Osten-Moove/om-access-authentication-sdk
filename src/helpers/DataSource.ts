import { DataSource, DataSourceOptions } from 'typeorm'
import { LoginEntity, LoginLogEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'

export class AuthenticationDataSource extends DataSource {
  constructor(database: DataSourceOptions) {
    super({
      ...database,
      entities: [LoginEntity, LoginLogEntity],
      name: AuthorizationLibDefaultOwner,
    })
  }
}
