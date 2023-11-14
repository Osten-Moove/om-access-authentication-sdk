import * as bcrypt from 'bcrypt'
import { Column, CreateDateColumn, Entity, JoinColumn, OneToOne, PrimaryColumn, UpdateDateColumn } from 'typeorm'
import { v4 } from 'uuid'
import { UserEntity } from './UserEntity'

@Entity({ name: 'access' })
export class LoginEntity<T extends string = string> {
  @PrimaryColumn('uuid')
  id: string

  @Column({ type: 'character varying', length: 50, unique: true })
  login: string

  @Column('character varying')
  password: string

  @Column({ type: 'boolean', name: 'is_active', default: true })
  isActive: boolean

  @Column({ type: 'uuid', generated: 'uuid', name: 'validation_token' })
  validationToken: string

  @Column({ type: 'uuid', generated: 'uuid', name: 'password_token' })
  passwordToken: string

  @Column({ type: 'character varying', length: 50, nullable: true, name: 'otp_token' })
  otpToken: string

  @Column({ type: 'character varying', array: true, name: 'roles', nullable: true })
  roles: Array<T>

  @CreateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'created_at' })
  createdAt: string

  @UpdateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'updated_at' })
  updatedAt: string

  @OneToOne(() => UserEntity, (user) => user.login, { cascade: ['insert', 'update', 'remove'] })
  @JoinColumn({ name: 'id' })
  user: UserEntity

  constructor(login: string, password: string = v4()) {
    this.login = login
    this.password = bcrypt.hashSync(password, 10)
  }
}
