export type ValidArgs = 'apply' | 'refresh' | 'config'
export type typeArgs = { [k in ValidArgs]?: string }

export type DecoratorConfig = {
  secret: string
  secondarySecret?: string
}
