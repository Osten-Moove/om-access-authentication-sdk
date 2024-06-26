export type ValidArgs = 'apply' | 'refresh' | 'config'
export type typeArgs = { [k in ValidArgs]?: string }
export type TupleResult<S, F> = [S | null, F | null]

export type DecoratorConfig = {
  secret: string
  secondarySecret?: string
  appName?: string
}
