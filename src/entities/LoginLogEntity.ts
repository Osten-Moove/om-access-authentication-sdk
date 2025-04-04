import { Logger } from '@nestjs/common'
import { BeforeInsert, Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm'
import { AuthenticationModule } from '../module/AuthenticationModule'
import { LoginEntity } from './LoginEntity'

@Entity({ name: 'login_logs' })
export class LoginLogEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column('uuid', { name: 'login_id', nullable: true, unique: false })
  loginId?: string

  @Column('character varying', { nullable: true })
  agent: string

  @Column('character varying', { name: 'ip_address', nullable: true })
  ipAddress: string

  @Column('character varying', { name: 'event_code' })
  eventCode: string

  @Column('character varying', { name: 'event_message' })
  eventMessage: string

  @CreateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'created_at' })
  createdAt: string

  @ManyToOne(() => LoginEntity)
  @JoinColumn({ name: 'login_id' })
  login?: LoginEntity

  constructor(loginId: string, agent: string) {
    this.loginId = loginId
    this.agent = agent
  }

  @BeforeInsert()
  beforeInsert() {
    if (AuthenticationModule.config.debug)
      Logger.debug(
        `LoginLogEntity::beforeInsert.loginId: ${this.loginId} agent: ${this.agent} ipAddress: ${this.ipAddress} eventCode: ${this.eventCode} eventMessage: ${this.eventMessage} createdAt: ${this.createdAt} login: ${this.login}`,
      )
  }
}
