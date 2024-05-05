package services

import (
	"fmt"
	"time"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

type TokenArgs struct {
	User      *dtos.JwtGenDTO
	Claims    *dtos.JwtCustomClaims
	ExpiresIn time.Duration
	RegClaims *jwt.RegisteredClaims
}

type TokensGen struct {
	AccessToken  *TokenArgs
	RefreshToken *TokenArgs
	Secret       string
}

func (args *TokenArgs) GenerateJWTToken(secret string) (string, error) {
	// Handle invalid claims or user
	if args.User == nil && args.Claims == nil {
		return "", fmt.Errorf("neither 'User' nor 'Claims' is provided")
	}
	if args.ExpiresIn == 0 {
		return "", fmt.Errorf("expiresIn must be non-zero")
	}

	regClaims := &jwt.RegisteredClaims{}
	if args.RegClaims != nil {
		regClaims = args.RegClaims
	}

	// Define the expiration time for the token
	expirationTime := time.Now().Add(args.ExpiresIn)
	regClaims.ExpiresAt = jwt.NewNumericDate(expirationTime)

	var claims jwt.Claims
	if args.User != nil {
		// Create the JWT claimsdto.Token
		claims = &dtos.JwtCustomClaims{
			UserID:           args.User.UserId,
			Username:         args.User.Username,
			Role:             args.User.Role,
			Email:            args.User.Email,
			RegisteredClaims: *regClaims,
		}

	} else if args.Claims != nil {
		validator := validator.New()
		if err := validator.Struct(args.Claims); err != nil {
			return "", err
		}
		claims = args.Claims
	} else {
		return "", fmt.Errorf("invalid claims or user")
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate token string using the secret key
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

func (tokens *TokensGen) GenerateTokens() (string, string, error) {
	// Create channels to receive the generated tokens and errors
	accTokenChan := make(chan string)
	refTokenChan := make(chan string)
	errChan := make(chan error, 2) // Buffered channel to avoid goroutine leaks

	// Generate access token in a goroutine
	go func() {
		accessToken, err := tokens.AccessToken.GenerateJWTToken(tokens.Secret)
		if err != nil {
			errChan <- err
			return
		}
		accTokenChan <- accessToken
	}()

	// Generate refresh token in a goroutine
	go func() {
		refreshToken, err := tokens.RefreshToken.GenerateJWTToken(tokens.Secret)
		if err != nil {
			errChan <- err
			return
		}
		refTokenChan <- refreshToken
	}()

	// Wait for both goroutines to finish and collect results
	var accessToken, refreshToken string
	for i := 0; i < 2; i++ {
		select {
		case accToken := <-accTokenChan:
			accessToken = accToken
		case refToken := <-refTokenChan:
			refreshToken = refToken
		case err := <-errChan:
			// Handle any errors here, such as logging or returning an error response
			return "", "", err
		}
	}
	return accessToken, refreshToken, nil
}
