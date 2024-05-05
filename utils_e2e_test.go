//go:build e2e_tests
// +build e2e_tests

package main_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/stretchr/testify/assert"
)

// Helper function to register a user
func RegisterUser(t *testing.T, CreateUserCredentialsDTO dtos.CreateUserCredentialsDTO) {
	// Marshal the request body to JSON
	requestBody, err := json.Marshal(CreateUserCredentialsDTO)
	assert.NoError(t, err)

	// Create a new HTTP request with the request body
	req, err := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(requestBody))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	assert.Equal(
		t,
		http.StatusCreated,
		rec.Code,
		"expected status code 201 for successful registration",
	)
}

// Helper function to login and assert the response
func LoginAndAssert(t *testing.T, loginDTO dtos.LoginDTO) dtos.TokenDTOResponse {
	// Marshal the request body to JSON
	requestBody, err := json.Marshal(loginDTO)
	assert.NoError(t, err)

	// Create a new HTTP request with the request body
	req, err := http.NewRequest("POST", path+"/login", bytes.NewBuffer(requestBody))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, rec.Code, "expected status code 200 for successful login")

	// Unmarshal the response body into a DTO
	var loginResponse dtos.TokenDTOResponse
	err = json.Unmarshal(rec.Body.Bytes(), &loginResponse)
	assert.NoError(t, err)

	// Assert that the access token is not empty
	assert.NotEmpty(t, loginResponse.Token, "access token should not be empty")
	return loginResponse
}
