import { randomUUID } from 'node:crypto'
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm'

@Entity({ name: 'api_keys' })
export class ApiKeyEntity<T extends string = string> {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column({ type: 'character varying', length: 40, name: 'public_key', nullable: true })
  publicKey: string

  @Column({ type: 'character varying', name: 'secret_key', unique: true, length: 255 })
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

  constructor(entity?: { isActive?: boolean; alias?: string; roles?: Array<T>; apiKey?: string }) {
    if (!entity) return
    if (entity.alias) this.alias = entity.alias
    if (entity.isActive) this.isActive = entity.isActive
    if (entity.roles) this.roles = entity.roles

    this.id = randomUUID()
  }
}
