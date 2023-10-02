import { DataSource, DataSourceOptions } from 'typeorm'
import { LoginEntity, LoginLogEntity, UserEntity } from '../entities'
import { AuthorizationLibDefaultOwner } from '../helpers/AuthorizationLibVariables'

export class AuthenticationDataSource extends DataSource {
  constructor(database: DataSourceOptions) {
    super({
      ...database,
      entities: [LoginEntity, LoginLogEntity, UserEntity],
      name: AuthorizationLibDefaultOwner,
    })
  }
}
