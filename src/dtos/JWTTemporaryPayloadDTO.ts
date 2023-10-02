export class JWTTemporaryPayloadDTO {
  id: string
  type: string
  pin?: string
  validationToken: string
  passwordToken: string

  constructor(payload: Partial<JWTTemporaryPayloadDTO>) {
    this.id = payload.id
    this.pin = payload.pin
    this.type = payload.type
    this.validationToken = payload.validationToken
    this.passwordToken = payload.passwordToken
  }

  static createPayload(payload: Partial<JWTTemporaryPayloadDTO>) {
    return { payload: new JWTTemporaryPayloadDTO(payload) }
  }

  static matchesObject(data?: Partial<JWTTemporaryPayloadDTO>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id', 'step']
    if (!keys.some((it) => requiredKeys.includes(it))) return false
    return true
  }
}
