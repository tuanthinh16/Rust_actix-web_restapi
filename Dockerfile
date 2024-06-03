# Stage 1: Build the Rust application
FROM rust:latest as builder

WORKDIR /app

# Copy the source code into the container
COPY . .

# Build the application
RUN cargo build --release

# Stage 2: Create a minimal image with the built binary
FROM debian:buster-slim

WORKDIR /app

# Copy the binary from the build stage
COPY --from=builder /app/target/release/your_project_executable /usr/local/bin/your_project_executable

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["your_project_executable"]
