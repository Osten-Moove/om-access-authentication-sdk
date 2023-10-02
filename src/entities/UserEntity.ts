import { Column, Entity, OneToOne, PrimaryGeneratedColumn } from 'typeorm'
import { LoginEntity } from './LoginEntity'

@Entity({ name: 'users' })
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column({ type: 'character varying', name: 'email' })
  email: string

  @Column({ type: 'character varying', name: 'full_name', nullable: true })
  fullName: string

  @OneToOne(() => LoginEntity, (login) => login.user)
  login: LoginEntity
}
