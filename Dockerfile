# Build stage
# We use the latest Rust stable release as base image
FROM lukemathwalker/cargo-chef:latest-rust-1.93.0-slim AS chef
WORKDIR /app
# Install the required system dependencies for our linking configuration
RUN apt update && apt install -y \
    lld \
    clang \
    pkg-config \
    libssl-dev

FROM chef AS planner
# Copy all files from our working environment to our Docker image
COPY . .
# Compute a lock-like file for our project
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build our project dependencies, not our application!
RUN cargo chef cook --release --recipe-path recipe.json
# Up to this point, if our dependency tree stays the same,
# all layers should be cached.
COPY . .
ENV SQLX_OFFLINE=true

# Build our project
# Let's build our binary!
# We'll use the release profile to make it fast
RUN cargo build --release --bin authpractice

# Pre Runtime stage
FROM debian:bullseye-slim AS preruntime
WORKDIR /app
RUN apt-get update -y \
&& apt-get install -y --no-install-recommends openssl ca-certificates \
# Clean up
&& apt-get autoremove -y \
&& apt-get clean -y \
&& rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/authpractice authpractice
COPY configuration configuration

FROM gcr.io/distroless/cc AS runtime
WORKDIR /app
# Copy the compiled binary from the builder environment
# to our runtime environment
COPY --from=builder /app/target/release/authpractice authpractice
COPY configuration configuration
ENV APP_ENVIRONMENT=production
ENTRYPOINT ["./authpractice"]
