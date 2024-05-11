# Use the official Golang image as the base image
FROM golang:1.22-alpine AS builder

RUN apk update && apk add --no-cache make

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the working directory
COPY go.mod go.sum Makefile ./

# Download and install Go dependencies
RUN make dep

# Copy the entire source code to the working directory
COPY . .

# Build the Go application
RUN make build

# Use a minimal Alpine image as the base image for the final build
FROM alpine:latest

RUN apk update && apk add bash

# Set the working directory inside the container
WORKDIR /app

# Copy the built Go application from the builder stage to the final image
COPY --from=builder /app/goauthx-linux .
COPY .env .


# Expose port 1234 for the Echo HTTP server
EXPOSE ${APP_PORT}
EXPOSE 5433


# Command to run the Go application
CMD ["./goauthx-linux"]