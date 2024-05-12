BINARY_NAME=goauthx

build:
	GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME}-linux ./cmd/main.go

run: build
	./${BINARY_NAME}

clean:
	go clean
	rm ${BINARY_NAME}-linux

test:
	go test ./...

test_e2e:
	go test ./e2e/auth_e2e_test.go -tags=e2e_tests

test_e2e_ci:
	go test ./e2e/auth_e2e_test.go -tags=e2e_tests -exec CI=true

test_coverage:
	go test ./... -coverprofile=coverage.out

dep:
	go mod download

vet:
	go vet

lint:
	golangci-lint run --enable-all