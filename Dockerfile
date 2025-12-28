# ============================================================================
# Multi-stage Dockerfile for GitLab Sync Monitor
# Security Hardened - Phase 1
# ============================================================================

# ============================================================================
# Stage 1: Build Frontend
# ============================================================================
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package*.json ./

# Install dependencies (using npm install for flexibility)
RUN npm install --production

# Copy frontend source
COPY frontend/ ./

# Build frontend
RUN npm run build

# ============================================================================
# Stage 2: Build Backend
# ============================================================================
FROM node:18-alpine AS backend-builder

WORKDIR /app/backend

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++ git

# Copy backend package files
COPY backend/package*.json ./

# Install dependencies (using npm install for flexibility)
RUN npm install --production

# ============================================================================
# Stage 3: Production Image
# ============================================================================
FROM node:18-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    git \
    openssh-client \
    ca-certificates \
    tini

# Create app user (security best practice - don't run as root)
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

# Set working directory
WORKDIR /app

# Copy backend from builder
COPY --from=backend-builder /app/backend ./backend

# Copy frontend build from builder
COPY --from=frontend-builder /app/frontend/build ./frontend/build

# Copy backend source code
COPY backend/server.js ./backend/

# Create required directories with proper permissions
RUN mkdir -p /data/repos /home/appuser && \
    chown -R appuser:appuser /app /data /home/appuser

# Switch to non-root user
USER appuser

# Set HOME environment variable for git config
ENV HOME=/home/appuser

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3001/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Set working directory to backend
WORKDIR /app/backend

# Environment variable for corporate SSL certificates (if needed)
# Can be overridden via deployment env vars
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

# Use tini as init system (handles signals properly)
ENTRYPOINT ["/sbin/tini", "--"]

# Start application
CMD ["node", "server.js"]
