import * as bcrypt from 'bcrypt'
import { BeforeInsert, Column, CreateDateColumn, Entity, PrimaryColumn, UpdateDateColumn } from 'typeorm'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { Logger } from '@duaneoli/logger'

@Entity({ name: 'access' })
export class LoginEntity<T extends string = string> {
  @PrimaryColumn('uuid')
  id: string

  @Column({ type: 'character varying', length: 255, unique: true })
  login: string

  @Column('character varying')
  password: string

  @Column({ type: 'boolean', name: 'is_active', default: true })
  isActive: boolean

  @Column({ type: 'character varying', name: 'email' })
  email: string

  @Column({ type: 'character varying', name: 'full_name', nullable: true })
  fullName: string

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

  constructor(entity?: {
    id?: string
    login?: string
    password?: string
    isActive?: boolean
    email?: string
    fullName?: string
    roles?: Array<T>
  }) {
    if (!entity) return
    if (entity.id) this.id = entity.id
    if (entity.login) this.login = entity.login
    if (entity.isActive) this.isActive = entity.isActive
    if (entity.email) this.email = entity.email
    if (entity.fullName) this.fullName = entity.fullName
    if (entity.roles) this.roles = entity.roles
    if (entity.password) this.password = bcrypt.hashSync(entity.password, 10)
  }

  @BeforeInsert()
  beforeInsert() {
    if (AuthenticationModule.config.debug)
      Logger.debug(
        `LoginEntity::beforeInsert.id: ${this.id} login: ${this.login} isActive: ${this.isActive} email: ${this.email} fullName: ${this.fullName} roles: ${this.roles} createdAt: ${this.createdAt} updatedAt: ${this.updatedAt}`,
      )
  }
}
