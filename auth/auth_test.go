package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacuBar/bookstore_utils-go/auth/oauthpb"
	"github.com/FacuBar/bookstore_utils-go/rest_errors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type oauthSCmock struct{}

var (
	funcValidateToken func(context.Context, *oauthpb.ValidateTokenRequest, ...grpc.CallOption) (*oauthpb.ValidateTokenResponse, error)
)

func (m *oauthSCmock) ValidateToken(ctx context.Context, in *oauthpb.ValidateTokenRequest, opts ...grpc.CallOption) (*oauthpb.ValidateTokenResponse, error) {
	return funcValidateToken(ctx, in)
}

func TestRequiresAuth(t *testing.T) {
	t.Run("NoAuthorizationHeader", func(t *testing.T) {
		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) { c.Status(200) }, nil))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		err, _ := rest_errors.NewRestErrorFromBytes(body)

		assert.NotNil(t, err)
		assert.EqualValues(t, "no authorization header was provided", err.Message())
	})

	t.Run("InvalidAuthorizationHeader", func(t *testing.T) {
		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) { c.Status(200) }, nil))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Add("Authorization", "abc")
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		err, _ := rest_errors.NewRestErrorFromBytes(body)

		assert.NotNil(t, err)
		assert.EqualValues(t, "invalid authorization header format", err.Message())
	})

	t.Run("AuthorizationTypeNotSupported", func(t *testing.T) {
		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) { c.Status(200) }, nil))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Add("Authorization", "notabearer abcd1234")
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		err, _ := rest_errors.NewRestErrorFromBytes(body)

		assert.NotNil(t, err)
		assert.EqualValues(t, "authorization type not supported", err.Message())
	})

	t.Run("InvalidAtInternalServerError", func(t *testing.T) {
		funcValidateToken = func(c context.Context, vtr *oauthpb.ValidateTokenRequest, co ...grpc.CallOption) (*oauthpb.ValidateTokenResponse, error) {
			return nil, status.Error(codes.Internal, "internal srv error")
		}

		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) { c.Status(200) }, &oauthSCmock{}))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Add("Authorization", "Bearer token1234")
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		err, _ := rest_errors.NewRestErrorFromBytes(body)

		assert.NotNil(t, err)
		fmt.Printf("%#v\n", err)
		assert.EqualValues(t, "couldn't verify session's validity", err.Message())
	})

	t.Run("UnauthorizedError", func(t *testing.T) {
		funcValidateToken = func(c context.Context, vtr *oauthpb.ValidateTokenRequest, co ...grpc.CallOption) (*oauthpb.ValidateTokenResponse, error) {
			return nil, status.Error(codes.NotFound, "access_token not found")
		}

		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) { c.Status(200) }, &oauthSCmock{}))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Add("Authorization", "Bearer token1234")
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		err, _ := rest_errors.NewRestErrorFromBytes(body)

		assert.NotNil(t, err)
		fmt.Printf("%#v\n", err)
		assert.EqualValues(t, "you are not logged in", err.Message())
	})

	t.Run("NoError", func(t *testing.T) {
		funcValidateToken = func(c context.Context, vtr *oauthpb.ValidateTokenRequest, co ...grpc.CallOption) (*oauthpb.ValidateTokenResponse, error) {
			return &oauthpb.ValidateTokenResponse{
				UserPayload: &oauthpb.ValidateTokenResponse_UserPayload{
					UserId: 1,
					Role:   1,
				},
			}, nil
		}

		resp := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, r := gin.CreateTestContext(resp)

		r.GET("/test", RequiresAuth(func(c *gin.Context) {
			authorizedUser := c.MustGet(userPayloadKey).(userPayload)
			c.JSON(200, authorizedUser)
		}, &oauthSCmock{}))

		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Add("Authorization", "Bearer token1234")
		r.ServeHTTP(resp, c.Request)

		body, _ := ioutil.ReadAll(resp.Body)
		var uPayload userPayload
		json.Unmarshal(body, &uPayload)

		assert.EqualValues(t, 1, uPayload.Id)

		assert.EqualValues(t, 200, resp.Code)
	})
}
