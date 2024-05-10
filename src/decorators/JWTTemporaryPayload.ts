import { ExecutionContext, createParamDecorator } from "@nestjs/common"
import type { RequestAuthorization } from "../types/LoginTypes"

export const JWTTemporaryPayload = createParamDecorator(
    (_: never, context: ExecutionContext) => {
      const request = context.switchToHttp().getRequest<RequestAuthorization>()
  
      return request.processedTemporaryPayloadDTO
    },
  )