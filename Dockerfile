# SSTI Scanner Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd --gid 1000 scanner && \
    useradd --uid 1000 --gid scanner --shell /bin/bash --create-home scanner

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Copy source code
COPY . .

# Install the package
RUN pip install -e .

# Create directories for output
RUN mkdir -p /app/output /app/config && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Set default config path
ENV SSTI_CONFIG_PATH=/app/config/default.yml

# Expose any ports if needed (none for CLI tool)
# EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import ssti_scanner; print('OK')" || exit 1

# Default command
ENTRYPOINT ["ssti-scanner"]
CMD ["--help"]

# Labels
LABEL maintainer="Samir Djili <samir.djili@example.com>" \
      description="Advanced Server-Side Template Injection (SSTI) vulnerability scanner" \
      version="1.0.0" \
      org.opencontainers.image.title="SSTI Scanner" \
      org.opencontainers.image.description="Advanced SSTI vulnerability scanner" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://github.com/samir-djili/ssti-scanner"
