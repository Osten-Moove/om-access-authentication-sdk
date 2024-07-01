export class JWTApiPayloadDTO{
  id: string
  alias?: string
  roles?: Array<string>
  isActive?: boolean

  constructor(payload: Partial<JWTApiPayloadDTO>) {
    this.id = payload.id
    this.alias = payload.alias
    this.roles = payload.roles
    this.isActive = payload.isActive
  }

  static createPayload<T>(payload: Partial<JWTApiPayloadDTO>) {
    return { payload: new JWTApiPayloadDTO(payload) }
  }

  static matchesObject<T>(data?: Partial<JWTApiPayloadDTO>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id']
    if (!keys.some((it) => requiredKeys.includes(it))) return false
    return true
  }
}
