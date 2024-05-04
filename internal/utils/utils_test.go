package utils_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/axdbertuol/auth_service/internal/utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGenerateSecureTokenWithExpiration(t *testing.T) {
	// t.Parallel()
	viper.Set("SECRET_HASH_EMAIL", "123")
	t.Run("time should be correct",
		func(t *testing.T) {
			// t.Parallel()
			tokenExp, _ := utils.GenerateSecureTokenWithExpiration("bla", time.Hour*12)
			decoded, _ := utils.DecodeString(*tokenExp)
			split := strings.Split(*decoded, ":")

			unixTimestamp, err := strconv.ParseInt(split[2], 10, 64)
			if err != nil {
				t.Fatal("Error parsing timestamp")
				return
			}
			now := time.Now().Add(12 * time.Hour).Local()
			assert.Equal(
				t,
				now.Day(),
				time.Unix(unixTimestamp, 0).Local().Day(),
			)
			assert.Equal(
				t,
				now.Hour(),
				time.Unix(unixTimestamp, 0).Local().Hour(),
			)
			assert.Equal(
				t,
				now.Minute(),
				time.Unix(unixTimestamp, 0).Local().Minute(),
			)
		},
	)
	t.Run("token should be correct", func(t *testing.T) {
		// t.Parallel()
		token, _ := utils.GenerateSecureTokenWithExpiration("bla", time.Hour*12)
		decoded, _ := utils.DecodeString(*token)

		split := strings.Split(*decoded, ":")

		assert.Equal(t, split[0], "bla")
		assert.Equal(t, split[1], "123")

	})

}

func TestGenerateUniqueToken(t *testing.T) {

	token, err := utils.GenerateUniqueToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
