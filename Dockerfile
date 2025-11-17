# syntax=docker/dockerfile:1.4
# BeaconAuth Server - Runtime Docker Image
# This Dockerfile uses pre-built musl binaries from the CI/CD pipeline.
# Binaries should be placed in the binaries/ directory before building.

FROM alpine:latest

ARG TARGETARCH

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates

# Copy pre-built binary from binaries directory
COPY binaries/beacon /usr/local/bin/beacon

# Set permissions
RUN chmod +x /usr/local/bin/beacon

# Create application directories
RUN mkdir -p /app/data /app/config

# Set working directory
WORKDIR /app

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/.well-known/jwks.json || exit 1

# Run BeaconAuth server
# Note: Database and config should be provided via environment variables or mounted volumes
ENTRYPOINT ["beacon"]
CMD ["serve"]
