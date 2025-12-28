FROM registry.access.redhat.com/ubi9/nodejs-18:latest

USER 0

# Install build tools needed for better-sqlite3
RUN yum install -y python3 make gcc gcc-c++ && \
    yum clean all

# Create app directory
WORKDIR /app

# Copy the application tar file
COPY gitlab-sync-monitor.tar.gz /tmp/

# Extract the application
RUN cd /tmp && \
    tar -xzf gitlab-sync-monitor.tar.gz && \
    mv gitlab-sync-monitor/backend /app/monitor && \
    rm -rf /tmp/gitlab-sync-monitor.tar.gz /tmp/gitlab-sync-monitor

# Remove any existing node_modules (from local machine)
RUN rm -rf /app/monitor/node_modules

# Configure npm for proxy environments
RUN npm config set registry http://registry.npmjs.org/ && \
    npm config set strict-ssl false

# Install dependencies with specific better-sqlite3 version
WORKDIR /app/monitor
RUN npm install better-sqlite3@7.6.2 --build-from-source && \
    npm install --only=production && \
    npm cache clean --force

# Create data directory for SQLite database
RUN mkdir -p /app/monitor/data

# Create non-root user
RUN useradd -r -u 1001 -g 0 nodejs && \
    chown -R 1001:0 /app && \
    chmod -R g=u /app

# Switch to non-root user
USER 1001

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the application
CMD ["node", "server.js"]
