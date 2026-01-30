# Multi-stage build for minimal image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o autosecscan cmd/autosecscan/*.go

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/autosecscan /usr/local/bin/autosecscan

# Create reports directory with correct permissions
RUN mkdir -p /app/reports && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Set entrypoint
ENTRYPOINT ["autosecscan"]

# Default command shows help
CMD ["--help"]

# Metadata
LABEL maintainer="Elysian0987" \
      description="AutoSecScan - Automated Web Security Audit Tool" \
      version="1.0.0"
