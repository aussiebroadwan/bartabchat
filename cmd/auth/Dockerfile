# =============================================================================
# Stage: base
#
# Build the base image with the necessary tools so that it can be used in the 
# build stage without having to install them again. 
# =============================================================================
FROM golang:alpine AS base

WORKDIR /usr/src/app

RUN apk update && apk upgrade && apk add --no-cache ca-certificates \
    && update-ca-certificates

# =============================================================================
# Stage: build
#
# Download project dependencies, and build the project.
# =============================================================================
FROM base AS build

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading 
# them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify


# copy the rest of the source code and build
COPY . .

RUN CGO_ENABLED=0 go build -v -o /bin/auth ./cmd/auth

# =============================================================================
# Stage: release
#
# Copy the built binary and the necessary certificates to a scratch image to
# reduce the image size.
# =============================================================================
FROM scratch AS release

COPY --from=build /bin/auth /bin/auth
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

CMD ["/bin/auth"]