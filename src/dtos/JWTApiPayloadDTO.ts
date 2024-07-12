export class JWTApiPayloadDTO<T extends Record<string,any> | null = null >{
  id: string
  alias?: string
  roles?: Array<string>
  isActive?: boolean
  moreInfo?: T 

  constructor(payload: Partial<JWTApiPayloadDTO<T>>) {
    this.id = payload.id
    this.alias = payload.alias
    this.roles = payload.roles
    this.isActive = payload.isActive
    this.moreInfo = payload.moreInfo
  }

  static createPayload<T>(payload: Partial<JWTApiPayloadDTO<T>>) {
    return { payload: new JWTApiPayloadDTO<T>(payload) }
  }

  static matchesObject<T>(data?: Partial<JWTApiPayloadDTO<T>>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id']
    if (!keys.some((it) => requiredKeys.includes(it))) return false
    return true
  }
}
