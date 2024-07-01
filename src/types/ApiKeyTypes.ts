export type GenerateApiKeyRequest = {
  isActive?: boolean
  alias?: string
  roles?: Array<string>
}

export type UpdateApiKeyRequest = {
  id: string
  alias?: string
  roles?: Array<string>
}

export type ApiKeyOptionsRequest = {
  ipAddress?: string
  agent?: string
  eventScope?: string
}