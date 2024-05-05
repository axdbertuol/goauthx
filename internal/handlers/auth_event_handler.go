package handlers

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/services"
	kafka "github.com/axdbertuol/goauthx/internal/services/kafka_consumer"

	"github.com/go-playground/validator/v10"
)

type AuthEventHandler struct {
	Handler
	authService services.AuthServicer
	validator   *validator.Validate
	logger      *slog.Logger
}

func (aeh *AuthEventHandler) SwitchEvents(event kafka.Event) error {
	log.Printf("%v", event)
	switch event.Type {
	case "user_created":
		return aeh.handleUserCreatedEvent(event)
	case "user_deleted":
		return aeh.handleUserDeletedEvent(event)
	case "user_updated":
		return aeh.handleUserUpdatedEvent(event)
	default:
		log.Printf("Unknown event type: %s", event.Type)
	}
	return nil
}

func NewAuthEventHandler(
	authService services.AuthServicer,
	logger *slog.Logger,
) *AuthEventHandler {

	return &AuthEventHandler{
		authService: authService,
		validator:   validator.New(),
		logger:      logger,
	}
}

func (aeh *AuthEventHandler) handleUserCreatedEvent(e kafka.Event) error {
	// map data to struct
	payload, err := kafka.MapToUserCreatePayload(e.Payload)
	if err != nil {
		aeh.logger.Error("map to user payload for event %v failed", e.Type, err)
		return err
	}
	// validate
	if err := aeh.validator.Struct(payload); err != nil {
		aeh.logger.Error("validate payload for event %v failed", e.Type, err)
		return err
	}

	ucreds := new(models.UserCredentials)
	if err := aeh.authService.CreateUserCredentials(
		ucreds,
		(*dtos.CreateUserCredentialsDTO)(payload),
	); err != nil {
		aeh.logger.Error("error creating user for event %v", e.Type, err)
		return err
	}

	return nil
}

func (aeh *AuthEventHandler) handleUserDeletedEvent(e kafka.Event) error {

	payload, err := kafka.MapToUserCreatePayload(e.Payload)

	if err != nil {
		aeh.logger.Error("map to user payload for event %v failed", e.Type, err)
		return err
	}
	// validate
	if err := aeh.validator.Struct(payload); err != nil {
		aeh.logger.Error("validate payload for event %v failed", e.Type, err)
		return err
	}

	if err := aeh.authService.DeleteUserCredentials(payload.UserId); err != nil {
		aeh.logger.Error("error creating user for event %v", e.Type, err)
		return err
	}

	return nil

}

func (aeh *AuthEventHandler) handleUserUpdatedEvent(e kafka.Event) error {
	payload, err := kafka.MapToUserUpdatePayload(e.Payload)
	if err != nil {
		aeh.logger.Error("map to user payload for event %v failed", e.Type, err)
		return err
	}
	// validate
	if err := aeh.validator.Struct(payload); err != nil {
		aeh.logger.Error("validate payload for event %v failed", e.Type, err)
		return err
	}

	// use db
	ucreds := new(models.UserCredentials)
	ucreds.UserId = payload.UserId
	aeh.logger.Info(fmt.Sprintf("%+v", ucreds))
	if err := aeh.authService.UpdateUserCredentials(ucreds, (*dtos.UpdateUserCredentialsDTO)(payload)); err != nil {
		aeh.logger.Error("error creating user for event %v", e.Type, err)
		return err
	}

	return nil
}
