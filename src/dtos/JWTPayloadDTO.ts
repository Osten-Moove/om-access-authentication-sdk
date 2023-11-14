export class JWTPayloadDTO<T extends string = string> {
  id: string
  type: 'ACCESS' | 'REFRESH'
  validationToken: string
  passwordToken: string
  roles?: Array<T>

  constructor(payload: Partial<JWTPayloadDTO>) {
    this.id = payload.id
    this.type = payload.type
    this.validationToken = payload.validationToken
    this.passwordToken = payload.passwordToken
    this.roles = payload.roles as Array<T>
  }

  static createPayload(payload: Partial<JWTPayloadDTO>) {
    return { payload: new JWTPayloadDTO(payload) }
  }

  static matchesObject(data?: Partial<JWTPayloadDTO>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id', 'validationToken', 'type']
    if (!keys.some((it) => requiredKeys.includes(it))) return false
    return true
  }
}
