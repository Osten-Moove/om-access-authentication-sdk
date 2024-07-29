export class JWTDynamicPayloadDTO<T extends Record<string, any> | null = null > {
  type: string
  pin?: string
  moreInfo?: T


  constructor(payload: Partial<JWTDynamicPayloadDTO<T>>) {
    this.pin = payload.pin
    this.type = payload.type
    this.moreInfo = payload.moreInfo
  }

  static createPayload<R>(payload: Partial<JWTDynamicPayloadDTO<R>>) {
    return { payload: new JWTDynamicPayloadDTO(payload) }
  }

  static matchesObject<R>(data?: Partial<JWTDynamicPayloadDTO<R>>): boolean {
    if (!data) return false
    const keys = Object.keys(data)
    const requiredKeys = ['id', 'type']
    if (keys.some((it) => !requiredKeys.includes(it))) return false
    return true
  }
  
}
