package dtos

import "encoding/json"

type JSONMarshaler interface {
	ToJSON() (string, error)
}
type Event struct {
	ID      string      `json:"id"`
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type UserCreatePayload struct {
	UserId   string `json:"userId"   validate:"required,gte=1"`
	Username string `json:"username" validate:"required,min=4"`
}
type UserUpdatePayload struct {
	UserId   string  `json:"userId"             validate:"required,gte=1"`
	Username *string `json:"username,omitempty" validate:"omitnil,min=4"`
}

func (e Event) ToJSON() (string, error) {
	return marshalJSON(e)
}

func (up UserCreatePayload) ToJSON() (string, error) {
	return marshalJSON(up)
}

func (uup UserUpdatePayload) ToJSON() (string, error) {
	return marshalJSON(uup)
}

func marshalJSON(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
