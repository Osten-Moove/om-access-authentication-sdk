import { ExecutionContext, createParamDecorator } from "@nestjs/common"
import type { RequestAuthorization } from "../types/LoginTypes"

export const JWTPayload = createParamDecorator(
    (_: never, context: ExecutionContext) => {
      const request = context.switchToHttp().getRequest<RequestAuthorization>()
  
      return request.processedPayloadDTO
    },
  )