import { Injectable } from '@nestjs/common'
import { Repository } from 'typeorm'
import { UserEntity } from '../entities'
import { AuthenticationModule } from '../module/AuthenticationModule'

@Injectable()
export class UserService {
  private repository: Repository<UserEntity>

  constructor() {
    this.repository = AuthenticationModule.connection.getRepository(UserEntity)
  }
}
