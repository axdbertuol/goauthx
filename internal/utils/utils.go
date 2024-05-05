package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/nrednav/cuid2"
	"github.com/spf13/viper"
)

// GenerateHashedToken generates a hashed token from the given input.
func GenerateHashedToken(input string) (*string, error) {
	// Add some secret key for additional security
	secretKey := viper.GetString("SECRET_HASH_EMAIL")
	if secretKey == "" {
		return nil, fmt.Errorf("please provide a secret key")
	}
	// Concatenate the input with the secret key
	data := input + ":" + secretKey

	// Calculate the SHA-256 hash of the concatenated data
	hash := sha256.Sum256([]byte(data))

	// Encode the hash as a hexadecimal string
	hashedToken := hex.EncodeToString(hash[:])

	return &hashedToken, nil
}
func GenerateSecureTokenWithExpiration(input string, expiration time.Duration) (*string, error) {
	secretKey := viper.GetString("SECRET_HASH_EMAIL")
	if secretKey == "" {
		return nil, fmt.Errorf("please provide a secret key")
	}

	// Calculate expiration time based on the current time and provided expiration duration
	expirationTime := time.Now().Add(expiration).Local().Unix()

	data := input + ":" + secretKey + ":" + fmt.Sprint(expirationTime)

	// Encode the hash as a hexadecimal string
	hashedToken := hex.EncodeToString([]byte(data))

	// Encode expiration time as a Unix timestamp and concatenate it with the token

	return &hashedToken, nil
}

// GenerateHashedToken generates a hashed token from the given input.
func DecodeString(hexString string) (*string, error) {

	// Decode the hexadecimal string
	decodedBytes, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("Error decoding hexadecimal string:", err)
		return nil, err
	}

	// Convert the byte slice to a string
	decodedString := string(decodedBytes)

	return &decodedString, nil
}

func DecodeEmailHash(hexString string) (*string, int64, error) {

	decoded, err := DecodeString(hexString)
	if err != nil || decoded == nil {
		return nil, 0, errors.New("token invalid")
	}
	split := strings.Split(*decoded, ":")
	email := split[0]
	unixTimestamp, err := strconv.ParseInt(split[2], 10, 64)
	if err != nil || time.Unix(unixTimestamp, 0).Before(time.Now()) {
		return nil, 0, errors.New("token invalid or expired")
	}
	return &email, int64(unixTimestamp), nil
}

func GenerateCuid(fingerprint string, length int) (string, error) {
	len := length
	if len < 2 || len > 32 {
		len = 12
	}
	generate, err := cuid2.Init(

		// Adjust the length of generated id, min = 2, max = 32
		cuid2.WithLength(len),

		// Provide a custom fingerprint that will be used by the id generator to help prevent
		// collisions when generating id's in a distributed system.
		cuid2.WithFingerprint(fingerprint),
	)
	if err != nil {
		return "", err
	}
	return generate(), nil
}
func GenerateUniqueToken() (string, error) {
	const resetTokenLength = 32

	tokenBytes := make([]byte, resetTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

func ValidateJwt(token, secret string, options ...jwt.ParserOption) (*dtos.JwtCustomClaims, error) {
	// Create a new parser with default options
	parser := jwt.NewParser()

	// Apply additional options if provided
	for _, option := range options {
		option(parser)
	}

	// Parse the JWT token
	t, err := parser.ParseWithClaims(
		token,
		&dtos.JwtCustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate the token signature using the secret
			return []byte(secret), nil
		},
	)

	// Check for parsing errors
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			// Invalid signature error
			return nil, err
		}
		// Other parsing errors
		return nil, err
	}

	// Check if the token is valid
	if !t.Valid {
		return nil, errors.New("token is invalid")
	}

	// Extract custom claims from the token
	claims, ok := t.Claims.(*dtos.JwtCustomClaims)
	if !ok {
		return nil, errors.New("failed to extract claims from token")
	}

	// Token is valid, return the custom claims
	return claims, nil
}
func CreateVersionedApiPath(e *echo.Echo, version string) *echo.Group {
	apiGroup := e.Group("/api")
	versionGroup := apiGroup.Group("/" + version)
	return versionGroup
}
