export class JWTPayloadDTO {
  id: string
  type: 'ACCESS' | 'REFRESH'
  validationToken: string
  passwordToken: string

  constructor(payload: Partial<JWTPayloadDTO>) {
    this.id = payload.id
    this.type = payload.type
    this.validationToken = payload.validationToken
    this.passwordToken = payload.passwordToken
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
