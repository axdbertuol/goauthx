package services_test

// func TestGenerateTokens(t *testing.T) {
// 	// Mock arguments for testing
// 	usr := &dtos.JwtGenDTO{
// 		UserId:   "123",
// 		Username: "testuser",
// 		Role:     "user",
// 	}
// 	args := &services.TokensGen{
// 		AccessToken: &services.TokenArgs{
// 			User:      usr,
// 			ExpiresIn: time.Minute * 15,
// 		},
// 		RefreshToken: &services.TokenArgs{
// 			ExpiresIn: time.Hour * 24,
// 			User:      usr,
// 		},
// 	}

// 	// accessToken, refreshToken, err := services.GenerateTokens(args, "x")
// 	assert.NoError(t, err)
// 	assert.NotEmpty(t, accessToken)
// 	assert.NotEmpty(t, refreshToken)
// }
