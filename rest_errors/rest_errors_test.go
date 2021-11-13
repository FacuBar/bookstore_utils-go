package rest_errors

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetters(t *testing.T) {
	err := restErr{
		ErrMessage: "user not found",
		ErrStatus:  http.StatusNotFound,
		ErrError:   "error 1051: row not found",
	}

	t.Run("Error", func(t *testing.T) {
		result := err.Error()

		assert.EqualValues(t, "message: user not found - status: 404 - error: error 1051: row not found", result)
	})

	t.Run("Message", func(t *testing.T) {
		result := err.Message()

		assert.EqualValues(t, "user not found", result)
	})

	t.Run("Status", func(t *testing.T) {
		result := err.Status()

		assert.EqualValues(t, 404, result)
	})
}

func TestNew(t *testing.T) {
	t.Run("RestErr", func(t *testing.T) {
		result := NewRestError("something", 301, "error something")

		assert.EqualValues(t, "message: something - status: 301 - error: error something", result.Error())
	})

	t.Run("BadRequestError", func(t *testing.T) {
		result := NewBadRequestError("password field cannot be empty")

		assert.EqualValues(t, "message: password field cannot be empty - status: 400 - error: bad_request", result.Error())
	})

	t.Run("NotFound", func(t *testing.T) {
		result := NewNotFoundError("item not found")

		assert.EqualValues(t, "message: item not found - status: 404 - error: not_found", result.Error())
	})

	t.Run("Unauthorized", func(t *testing.T) {
		result := NewUnauthorizedError("you must be logged in")

		assert.EqualValues(t, "message: you must be logged in - status: 401 - error: unauthorized", result.Error())
	})

	t.Run("InternalServerError", func(t *testing.T) {
		result := NewInternalServerError("db error")

		assert.EqualValues(t, "message: db error - status: 500 - error: internal_server_error", result.Error())
	})

	t.Run("FromBytesError", func(t *testing.T) {
		bytes, _ := json.Marshal(`{status:"1"}`)
		result, err := NewRestErrorFromBytes(bytes)

		assert.Nil(t, result)
		assert.NotNil(t, err)
	})

	t.Run("FromBytesNoError", func(t *testing.T) {
		resultTemp := NewInternalServerError("db error")
		bytes, _ := json.Marshal(resultTemp)
		result, err := NewRestErrorFromBytes(bytes)

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.EqualValues(t, "message: db error - status: 500 - error: internal_server_error", result.Error())
	})
}
