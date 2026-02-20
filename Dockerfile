# syntax=docker/dockerfile:1

# Stage 1: Build Tailwind CSS
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies with layer caching
COPY package.json package-lock.json ./
COPY app/package.json app/package-lock.json ./app/
RUN npm ci && npm ci --prefix app

# Copy all source files
COPY wrangler.toml ./
COPY app/ ./app/

# Build minified Tailwind CSS
RUN cd app && npx tailwindcss -i src/tailwind-input.css -o src/static/tailwind.css --minify

# Stage 2: Runtime image
FROM node:20-alpine

LABEL org.opencontainers.image.title="WAF-Checker" \
      org.opencontainers.image.description="Test how well your WAF protects against common attack vectors" \
      org.opencontainers.image.source="https://github.com/PAPAMICA/waf-checker" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy built application from builder stage
COPY --from=builder /app ./

EXPOSE 8787

# Run wrangler dev server bound to all interfaces
CMD ["npx", "wrangler", "dev", "--ip", "0.0.0.0", "--port", "8787"]
