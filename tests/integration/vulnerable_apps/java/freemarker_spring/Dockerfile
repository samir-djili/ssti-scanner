# Dockerfile for FreeMarker Spring Vulnerable Test Application
FROM openjdk:11-jre-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Maven wrapper and POM file first for better caching
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

# Make Maven wrapper executable
RUN chmod +x mvnw

# Download dependencies (this layer will be cached if POM doesn't change)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw clean package -DskipTests

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Set JVM options
ENV JAVA_OPTS="-Xmx512m -Xms256m"

# Run the application
CMD ["java", "-jar", "target/freemarker-ssti-app-1.0.0.jar"]
