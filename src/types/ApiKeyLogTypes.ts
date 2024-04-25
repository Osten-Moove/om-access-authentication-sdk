export type RegisterApiKeyLogRequest = {
    apiKeyId: string
    eventCode: string
    eventMessage: string
    eventScope?: string
    agent?: string
    ipAddress?: string
}

export const ApiKeyLogEvents = {
    API_KEY_GENERATED: { code: 'API_KEY_GENERATED', message: 'A new api key was generated.' },
    API_KEY_REGENERATED: { code: 'API_KEY_REGENERATED', message: 'An api key was regenerated.' },
    API_KEY_ACTIVATED: { code: 'API_KEY_ACTIVATED', message: 'An api key was activated.' },
    API_KEY_DEACTIVATED: { code: 'API_KEY_DEACTIVATED', message: 'An api key was deactivated.' },
    API_KEY_REVOKED: { code: 'API_KEY_REVOKED', message: 'An api key was revoked.' },
}