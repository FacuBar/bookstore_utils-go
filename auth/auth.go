package auth

import (
	"context"
	"strings"

	"github.com/FacuBar/bookstore_utils-go/auth/oauthpb"
	"github.com/FacuBar/bookstore_utils-go/rest_errors"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	authHeaderKey  = "Authorization"
	userPayloadKey = "user_payload"
)

type userPayload struct {
	Id   int64  `json:"user_id"`
	Role string `json:"user_role"`
}

func RequiresAuth(handler gin.HandlerFunc, rpcC oauthpb.OauthServiceClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeader := c.GetHeader(authHeaderKey)
		if len(authorizationHeader) == 0 {
			err := rest_errors.NewBadRequestError("no authorization header was provided")
			c.AbortWithStatusJSON(err.Status(), err)
			return
		}

		authFields := strings.Split(authorizationHeader, " ")
		if len(authFields) != 2 {
			err := rest_errors.NewBadRequestError("invalid authorization header format")
			c.AbortWithStatusJSON(err.Status(), err)
			return
		}

		if authFields[0] != "Bearer" {
			err := rest_errors.NewBadRequestError("authorization type not supported")
			c.AbortWithStatusJSON(err.Status(), err)
			return
		}

		req := oauthpb.ValidateTokenRequest{AccessToken: authFields[1]}

		resp, err := rpcC.ValidateToken(context.Background(), &req)
		if err != nil {
			errStatus, _ := status.FromError(err)

			if codes.Internal != errStatus.Code() {
				restErr := rest_errors.NewUnauthorizedError("you are not logged in")
				c.AbortWithStatusJSON(restErr.Status(), restErr)
				return
			}

			restErr := rest_errors.NewUnauthorizedError("couldn't verify session's validity")
			c.AbortWithStatusJSON(restErr.Status(), restErr)
			return
		}

		user := userPayload{
			Role: strings.ToLower(oauthpb.ValidateTokenResponse_UserPayload_Role_name[int32(resp.GetUserPayload().GetRole())]),
			Id:   resp.GetUserPayload().GetUserId(),
		}

		c.Set(userPayloadKey, user)

		handler(c)
	}
}
