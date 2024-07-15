import { before } from 'node:test';
import { BeforeInsert, Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm'
import { ApiKeyEntity } from './ApiKeyEntity'
import { Logger } from '@duaneoli/logger';
import { AuthenticationModule } from '../module/AuthenticationModule';

@Entity({ name: 'api_key_logs' })
export class ApiKeyLogEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column('uuid', { name: 'api_key_id', nullable: true, unique: false })
  apiKeyId?: string

  @Column('character varying', { nullable: true })
  agent: string

  @Column('character varying', { name: 'ip_address', nullable: true })
  ipAddress: string

  @Column('character varying', { name: 'event_scope', nullable: true })
  eventScope: string

  @Column('character varying', { name: 'event_code' })
  eventCode: string

  @Column('character varying', { name: 'event_message' })
  eventMessage: string

  @CreateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'created_at' })
  createdAt: string

  @ManyToOne(() => ApiKeyEntity)
  @JoinColumn({ name: 'api_key_id' })
  apiKey?: ApiKeyEntity

  constructor(apiKeyId: string, agent: string) {
    this.apiKeyId = apiKeyId
    this.agent = agent
  }

  @BeforeInsert()
  beforeInsert() {
    if (AuthenticationModule.config.debug)
      Logger.debug(
        `ApiKeyLogEntity::beforeInsert.apiKeyId: ${this.apiKeyId} agent: ${this.agent} ipAddress: ${this.ipAddress} eventCode: ${this.eventCode} eventMessage: ${this.eventMessage} createdAt: ${this.createdAt} apiKey: ${this.apiKey}`,
      )
  }
}