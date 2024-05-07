import { randomUUID } from 'node:crypto'
import * as bcrypt from 'bcrypt'
import { Column, CreateDateColumn, Entity, PrimaryColumn, UpdateDateColumn } from 'typeorm'

@Entity({ name: 'api_keys' })
export class ApiKeyEntity<T extends string = string> {
  @PrimaryColumn('uuid')
  id: string

  @Column({ type: 'uuid', name: 'public_key', unique: true })
  publicKey: string

  @Column({ type: 'uuid', name: 'secret_key', unique: true })
  secretKey: string

  @Column({ type: 'boolean', name: 'is_active', default: true })
  isActive: boolean

  @Column({ type: 'character varying', name: 'alias', nullable: true })
  alias: string

  @Column({ type: 'character varying', array: true, name: 'roles', nullable: true })
  roles: Array<T>

  @CreateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'created_at' })
  createdAt: string

  @UpdateDateColumn({ type: 'timestamp without time zone', default: () => 'CURRENT_TIMESTAMP', name: 'updated_at' })
  updatedAt: string

  constructor(entity?: {
    isActive?: boolean
    alias?: string
    roles?: Array<T>
  }) {
    if (!entity) return
    if (entity.alias) this.alias = entity.alias
    if (entity.isActive) this.isActive = entity.isActive
    if (entity.roles) this.roles = entity.roles

    this.id = randomUUID()
    this.publicKey = randomUUID()
    this.secretKey = bcrypt.hashSync(randomUUID(), 10)
  }
}
