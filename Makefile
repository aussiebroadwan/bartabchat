.PHONY: test lint modernize sqlc swagger new-migrate-auth-sqlite dev help


# Default target - show help                                                                          
help:                                                                
	@echo "BarTab Development Commands"                                                                 
	@echo ""                                                                                            
	@echo "Usage: make [target]"                                                                        
	@echo ""                                                                                            
	@echo "Available targets:"                                                                          
	@echo "  help                     Show this help message"													
	@echo "  test                     Run all tests"
	@echo "  lint                     Run golangci-lint and fix issues quick linting issues"
	@echo "  modernize                Modernize code using gopls"
	@echo "  sqlc                     Generate code from SQL queries using sqlc"
	@echo "  new-migrate-auth-sqlite  Create a new migration for the auth sqlite store (set NAME=your_migration_name)"
	@echo "  dev                      Run all development checks (test, lint)"
	@echo ""

build: # Build the application
	@echo "Building application..."
	@mkdir -p ./bin
	@go build -o bin/auth ./cmd/auth/

test-unit: # Run unit tests this will need to be added to as more packages are added
	@echo "Running unit tests..."
	@go clean -testcache
	@go test -v ./internal/...
	@go test -v ./pkg/...

test-e2e: # Run end-to-end tests these use testcontainers to spin up temporary instances of dependent services
	@echo "Checking if Docker is running..."
	@docker info > /dev/null 2>&1 || (echo "Error: Docker is not running. Please start Docker and try again." && exit 1)
	@echo "Running tests..."
	@go clean -testcache
	@go test -v ./test/e2e/...

test: test-unit test-e2e
	@echo "All tests ran."

lint: # Run golangci-lint and fix issues quick linting issues
	@echo "Running linter..."
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0 run --fix ./...

modernize: # Modernize code using gopls
	@echo "Modernizing code..."
	@go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

swagger: # Generate swagger docs
	@echo "Generating swagger docs..."
	go run github.com/swaggo/swag/cmd/swag@latest fmt
	@go run github.com/swaggo/swag/cmd/swag@latest init -g internal/auth/http/router.go -o ./api/auth

sqlc: # Generate code from SQL queries using sqlc
	@echo "Generating SQL code..."
	@go run github.com/sqlc-dev/sqlc/cmd/sqlc@latest generate

new-migrate-auth-sqlite: # Create a new migration for the auth sqlite store (set NAME=your_migration_name)
	@if [ -z "$(NAME)" ]; then \
		echo "Error: NAME is required. Usage: make new-migrate-auth-sqlite NAME=migration_name"; \
		exit 1; \
	fi
	@echo "Creating new migration up/down file for auth sqlite store: $(NAME)"
	@go run github.com/golang-migrate/migrate/v4/cmd/migrate@latest create -ext sql -dir internal/auth/store/drivers/sqlite/migrations -seq $(NAME)

dev: test lint # Run all development checks (test, lint)
	@echo "Development checks passed."