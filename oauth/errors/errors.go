package errors

import (
	"errors"
	"net/http"
)

// RestErr error struct
type RestErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

func NewError(m string) error {
	return errors.New(m)
}

// NewBadRequest error message
func NewBadRequest(m string) *RestErr {
	return &RestErr{
		Message: m,
		Status:  http.StatusBadRequest,
		Error:   "bad_request",
	}
}

// NewNotFound error message
func NewNotFound(m string) *RestErr {
	return &RestErr{
		Message: m,
		Status:  http.StatusNotFound,
		Error:   "not_found",
	}
}

// NewInternalServerError error message
func NewInternalServerError(m string) *RestErr {
	return &RestErr{
		Message: m,
		Status:  http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}
