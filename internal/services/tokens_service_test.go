package services_test

import (
	"testing"
	"time"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestGenerateTokens(t *testing.T) {
	// Mock arguments for testing
	usr := &dtos.JwtGenDTO{
		UserId:   uint(123),
		Username: "testuser",
		Role:     "user",
	}
	args := &services.TokensGen{
		AccessToken: &services.TokenArgs{
			User:      usr,
			ExpiresIn: time.Minute * 15,
		},
		RefreshToken: &services.TokenArgs{
			ExpiresIn: time.Hour * 24,
			User:      usr,
		},
		Secret: "bla",
	}

	accessToken, refreshToken, err := args.GenerateTokens()
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
}
func BenchmarkGenerateTokens(b *testing.B) {
	usr := &dtos.JwtGenDTO{
		UserId:   uint(123),
		Username: "testuser",
		Role:     "user",
	}
	args := &services.TokensGen{
		AccessToken: &services.TokenArgs{
			User:      usr,
			ExpiresIn: time.Minute * 15,
		},
		RefreshToken: &services.TokenArgs{
			ExpiresIn: time.Hour * 24,
			User:      usr,
		},
		Secret: "bla",
	}

	for i := 0; i < b.N; i++ {
		_, _, _ = args.GenerateTokens()
	}
}
