export class JWTTemporaryPayloadDTO<T extends Record<string, any> | null = null > {
  id: string
  type: string
  pin?: string
  validationToken?: string
  passwordToken?: string
  moreInfo?: T


  constructor(payload: Partial<JWTTemporaryPayloadDTO<T>>) {
    this.id = payload.id
    this.pin = payload.pin
    this.type = payload.type
    this.validationToken = payload.validationToken
    this.passwordToken = payload.passwordToken
    this.moreInfo = payload.moreInfo
  }

  static createPayload<R>(payload: Partial<JWTTemporaryPayloadDTO<R>>) {
    return { payload: new JWTTemporaryPayloadDTO(payload) }
  }

  static matchesObject<R>(data?: Partial<JWTTemporaryPayloadDTO<R>>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id', 'type']
    if (keys.some((it) => !requiredKeys.includes(it))) return false
    return true
  }
}
