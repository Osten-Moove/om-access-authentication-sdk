export class JWTPayloadDTO<T extends Record<string,any> | null = null > {
  id: string
  type: 'ACCESS' | 'REFRESH'
  validationToken: string
  passwordToken: string
  moreInfo?: T 

  constructor(payload: Partial<JWTPayloadDTO<T>>) {
    this.id = payload.id
    this.type = payload.type
    this.validationToken = payload.validationToken
    this.passwordToken = payload.passwordToken
    this.moreInfo = payload.moreInfo
  }

  static createPayload<T>(payload: Partial<JWTPayloadDTO<T>>) {
    return { payload: new JWTPayloadDTO<T>(payload) }
  }

  static matchesObject<T>(data?: Partial<JWTPayloadDTO<T>>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id', 'validationToken', 'type']
    if (!keys.some((it) => requiredKeys.includes(it))) return false
    return true
  }
}
