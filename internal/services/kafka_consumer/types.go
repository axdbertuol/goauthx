package kafka_consumer

import "github.com/google/uuid"

type Event struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

type UserCreatePayload struct {
	UserId       uuid.UUID `json:"userId"                 validate:"required"`
	Username     string    `json:"username"               validate:"required"`
	Email        string    `json:"email"                  validate:"required,email"`
	PasswordHash []byte    `json:"passwordHash,omitempty" validate:"omitempty,required_without=SocialId"`
	Status       string    `json:"status"                 validate:"required"`
	Role         string    `json:"role"                   validate:"required"`
	SocialId     string    `json:"socialId,omitempty"     validate:"omitempty,required_without=PasswordHash"`
}
type UserUpdatePayload struct {
	UserId       uuid.UUID `json:"userId"                 validate:"required"`
	Username     *string   `json:"username,omitempty"     validate:"omitempty"`
	Email        *string   `json:"email,omitempty"        validate:"omitempty,email"`
	PasswordHash *[]byte   `json:"passwordHash,omitempty" validate:"omitempty"`
	Status       *string   `json:"status,omitempty"       validate:"omitempty"`
	Role         *string   `json:"role,omitempty"         validate:"omitempty"`
	SocialId     *string   `json:"socialId,omitempty"     validate:"omitempty"`
}

// Function to convert map[string]interface{} to UserCreatePayload struct
func MapToUserCreatePayload(data map[string]interface{}) (*UserCreatePayload, error) {
	var payload UserCreatePayload

	// Perform type assertions to extract values from the map

	if userId, ok := data["userId"].(string); data["userId"] != 0 && ok {
		parsedUuid, err := uuid.Parse(userId)
		if err != nil {
			return nil, err
		}
		payload.UserId = parsedUuid
	}
	if username, ok := data["username"].(string); data["username"] != "" && ok {
		payload.Username = username
	}
	if email, ok := data["email"].(string); data["email"] != "" && ok {
		payload.Email = email
	}
	if passwordHash, ok := data["passwordHash"].([]byte); data["passwordHash"] != "" && ok {
		payload.PasswordHash = passwordHash
	}
	if status, ok := data["status"].(string); data["status"] != "" && ok {
		payload.Status = status
	}
	if socialId, ok := data["socialId"].(string); data["socialId"] != "" && ok {
		payload.SocialId = socialId
	}
	if role, ok := data["role"].(string); data["role"] != "" && ok {
		payload.Role = role
	}

	return &payload, nil
}

// Function to convert map[string]interface{} to UserCreatePayload struct
func MapToUserUpdatePayload(data map[string]interface{}) (*UserUpdatePayload, error) {
	var payload UserUpdatePayload

	// Perform type assertions to extract values from the map

	if userId, ok := data["userId"].(string); data["userId"] != 0 && ok {
		parsedUuid, err := uuid.Parse(userId)
		if err != nil {
			return nil, err
		}
		payload.UserId = parsedUuid
	}
	if username, ok := data["username"].(*string); data["username"] != nil && ok {
		payload.Username = username
	}
	if email, ok := data["email"].(*string); data["email"] != nil && ok {
		payload.Email = email
	}
	if passwordHash, ok := data["passwordHash"].(*[]byte); data["passwordHash"] != nil && ok {
		payload.PasswordHash = passwordHash
	}
	if status, ok := data["status"].(*string); data["status"] != nil && ok {
		payload.Status = status
	}
	if socialId, ok := data["socialId"].(*string); data["socialId"] != nil && ok {
		payload.SocialId = socialId
	}

	return &payload, nil
}
