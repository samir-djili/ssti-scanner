# Vulnerable Applications for SSTI Testing

This directory contains intentionally vulnerable web applications designed to test the SSTI Scanner across all supported template engines. These applications are for testing purposes only and should **NEVER** be deployed in production environments.

## 🚨 Security Warning

**WARNING**: These applications contain intentional security vulnerabilities including Server-Side Template Injection (SSTI) flaws. They are designed exclusively for security testing and educational purposes. Do not deploy these applications in production or publicly accessible environments.

## 📁 Application Structure

```
vulnerable_apps/
├── python/                          # Python-based applications
│   ├── jinja2_flask/               # Flask application with Jinja2
│   │   ├── app.py                  # Main Flask application
│   │   ├── routes.py               # Route definitions
│   │   ├── requirements.txt        # Python dependencies
│   │   └── Dockerfile              # Docker container definition
│   └── django_templates/           # Django application with Django Templates
│       ├── app.py                  # Main Django application
│       ├── routes.py               # URL patterns and views
│       ├── requirements.txt        # Python dependencies
│       └── Dockerfile              # Docker container definition
├── php/                            # PHP-based applications
│   ├── twig_symfony/               # Symfony application with Twig
│   │   ├── app.php                 # Main Symfony application
│   │   ├── routes.php              # Route definitions
│   │   ├── composer.json           # PHP dependencies
│   │   └── Dockerfile              # Docker container definition
│   └── smarty/                     # PHP application with Smarty
│       ├── app.php                 # Main PHP application
│       ├── routes.php              # Route definitions
│       ├── composer.json           # PHP dependencies
│       └── Dockerfile              # Docker container definition
├── java/                           # Java-based applications
│   └── freemarker_spring/          # Spring Boot with FreeMarker
│       ├── src/                    # Java source code
│       ├── pom.xml                 # Maven dependencies
│       └── Dockerfile              # Docker container definition
├── docker-compose.yml              # Multi-container orchestration
├── manage_docker.sh                # Linux/macOS management script
├── manage_docker.ps1               # Windows PowerShell management script
└── README.md                       # This file
```

## 🐳 Docker Management

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ available RAM
- 10GB+ available disk space

### Quick Start

#### Linux/macOS
```bash
# Make the script executable
chmod +x manage_docker.sh

# Build all applications
./manage_docker.sh build

# Start all services
./manage_docker.sh start

# Check health status
./manage_docker.sh health

# Run integration tests
./manage_docker.sh test
```

#### Windows PowerShell
```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Build all applications
.\manage_docker.ps1 build

# Start all services
.\manage_docker.ps1 start

# Check health status
.\manage_docker.ps1 health

# Run integration tests
.\manage_docker.ps1 test
```

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `build` | Build all Docker images | `./manage_docker.sh build` |
| `start` | Start all services | `./manage_docker.sh start` |
| `stop` | Stop all services | `./manage_docker.sh stop` |
| `restart` | Restart all services | `./manage_docker.sh restart` |
| `status` | Show service status | `./manage_docker.sh status` |
| `logs [service]` | Show logs | `./manage_docker.sh logs jinja2-flask` |
| `health` | Run health checks | `./manage_docker.sh health` |
| `test` | Run integration tests | `./manage_docker.sh test` |
| `cleanup` | Clean up resources | `./manage_docker.sh cleanup` |
| `help` | Show help message | `./manage_docker.sh help` |

## 🌐 Application Endpoints

### Jinja2 Flask Application (Port 5000)
- **Base URL**: http://localhost:5000
- **Health Check**: http://localhost:5000/health
- **Vulnerable Endpoints**:
  - `/search?q=<payload>` - GET parameter injection
  - `/profile` - POST data injection in bio field
  - `/template` - Direct template rendering
  - `/error` - Error page template injection

### Django Templates Application (Port 8000)
- **Base URL**: http://localhost:8000
- **Health Check**: http://localhost:8000/health
- **Vulnerable Endpoints**:
  - `/search?query=<payload>` - GET parameter injection
  - `/user/<user_id>` - URL path injection
  - `/comment` - POST form injection
  - `/admin/debug` - Debug template injection

### Twig Symfony Application (Port 8001)
- **Base URL**: http://localhost:8001
- **Health Check**: http://localhost:8001/health
- **Vulnerable Endpoints**:
  - `/search?term=<payload>` - GET parameter injection
  - `/user/profile` - POST form injection
  - `/template/render` - Direct template rendering
  - `/filter/<filter_name>` - Filter-based injection

### Smarty PHP Application (Port 8002)
- **Base URL**: http://localhost:8002
- **Health Check**: http://localhost:8002/health
- **Vulnerable Endpoints**:
  - `/search.php?q=<payload>` - GET parameter injection
  - `/profile.php` - POST form injection
  - `/template.php` - Direct template compilation
  - `/math.php` - Mathematical expression injection

### FreeMarker Spring Application (Port 8080)
- **Base URL**: http://localhost:8080
- **Health Check**: http://localhost:8080/actuator/health
- **Vulnerable Endpoints**:
  - `/search?query=<payload>` - GET parameter injection
  - `/user/{userId}` - Path variable injection
  - `/template` - POST template rendering
  - `/expression` - Expression language injection

## 🧪 Testing Scenarios

Each application provides multiple vulnerability scenarios:

### 1. Mathematical Expression Injection
Test basic SSTI detection using mathematical expressions:
```bash
# Jinja2/Django/Twig
curl "http://localhost:5000/search?q={{7*7}}"

# Smarty
curl "http://localhost:8002/search.php?q={7*7}"

# FreeMarker
curl "http://localhost:8080/search?query=\${7*7}"
```

### 2. Object/Variable Disclosure
Test template engine object access:
```bash
# Jinja2 (Flask globals)
curl "http://localhost:5000/search?q={{config}}"

# Twig (environment access)
curl "http://localhost:8001/search?term={{_self.env}}"

# Django (settings access)
curl "http://localhost:8000/search?query={{settings.SECRET_KEY}}"
```

### 3. Function/Filter Execution
Test template engine function calls:
```bash
# Twig filters
curl "http://localhost:8001/search?term={{'test'|upper}}"

# Smarty functions
curl "http://localhost:8002/search.php?q={php}phpinfo(){/php}"

# FreeMarker methods
curl "http://localhost:8080/search?query=\${\"test\".toUpperCase()}"
```

### 4. Error-Based Detection
Test error message disclosure:
```bash
# Invalid syntax to trigger errors
curl "http://localhost:5000/search?q={{undefined_variable}}"
curl "http://localhost:8001/search?term={{invalid.syntax}}"
```

## 🔧 Configuration

### Environment Variables

Each application supports configuration through environment variables:

```bash
# Flask Application
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=test_key

# Django Application
DJANGO_SETTINGS_MODULE=settings
DEBUG=True

# Spring Application
SPRING_PROFILES_ACTIVE=test
JAVA_OPTS=-Xmx512m
```

### Port Configuration

Default ports can be changed in `docker-compose.yml`:

```yaml
services:
  jinja2-flask:
    ports:
      - "5000:5000"  # Host:Container
```

## 📊 Monitoring and Logging

### Health Checks

All applications include health check endpoints that return JSON status:

```json
{
  "status": "healthy",
  "timestamp": "2025-08-07T10:30:00Z",
  "application": "jinja2-flask",
  "version": "1.0.0"
}
```

### Log Access

View application logs in real-time:

```bash
# All services
./manage_docker.sh logs

# Specific service
./manage_docker.sh logs jinja2-flask

# Follow logs
docker-compose -p ssti-scanner-test logs -f jinja2-flask
```

### Resource Monitoring

Monitor container resource usage:

```bash
# Container stats
docker stats

# Specific containers
docker stats ssti-jinja2-flask ssti-django-templates
```

## 🧪 Integration with SSTI Scanner

### Automated Testing

The applications are designed to work seamlessly with the SSTI Scanner:

```bash
# Run scanner against all applications
python -m ssti_scanner.cli -u "http://localhost:5000/search?q=test"
python -m ssti_scanner.cli -u "http://localhost:8000/search?query=test"
python -m ssti_scanner.cli -u "http://localhost:8001/search?term=test"
python -m ssti_scanner.cli -u "http://localhost:8002/search.php?q=test"
python -m ssti_scanner.cli -u "http://localhost:8080/search?query=test"

# Batch scanning
echo "http://localhost:5000/search?q=test
http://localhost:8000/search?query=test
http://localhost:8001/search?term=test
http://localhost:8002/search.php?q=test
http://localhost:8080/search?query=test" > test_urls.txt

python -m ssti_scanner.cli --url-file test_urls.txt
```

### Test Scenarios

Each application includes specific test scenarios:

1. **Positive Tests**: Endpoints that should trigger SSTI detection
2. **Negative Tests**: Endpoints that should not trigger false positives
3. **Edge Cases**: Unusual input formats and encoding scenarios
4. **Performance Tests**: High-load testing scenarios

## 🛠️ Development

### Adding New Applications

To add support for additional template engines:

1. Create new directory: `vulnerable_apps/<language>/<engine>/`
2. Implement vulnerable application with standard endpoints
3. Create `Dockerfile` with proper configuration
4. Add service to `docker-compose.yml`
5. Update management scripts
6. Add integration tests

### Required Endpoints

Each vulnerable application must implement:

- `GET /health` - Health check endpoint
- `GET /search?q=<input>` - Basic GET parameter injection
- `POST /template` - Template rendering endpoint
- `GET /error` - Error handling test endpoint

### Testing Framework Integration

Applications integrate with pytest for automated testing:

```python
# Example test
def test_jinja2_math_injection():
    response = requests.get("http://localhost:5000/search?q={{7*7}}")
    assert "49" in response.text
    assert response.status_code == 200
```

## 🔒 Security Considerations

### Network Isolation

Applications run in an isolated Docker network:

```yaml
networks:
  ssti-test-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Resource Limits

Container resource limits prevent abuse:

```yaml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.5'
```

### Non-Root Execution

Applications run as non-root users when possible:

```dockerfile
RUN adduser --disabled-password --gecos '' appuser
USER appuser
```

## 📈 Performance Optimization

### Image Optimization

- Multi-stage builds for smaller images
- Layer caching for faster builds
- Minimal base images (alpine, slim)

### Startup Optimization

- Health checks with appropriate timeouts
- Dependency pre-installation
- Parallel service startup

### Resource Efficiency

- Shared volumes for common data
- Network optimization
- Memory-efficient configurations

## 🐛 Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :5000

# Use different ports
docker-compose -f docker-compose.yml -p test up -d --force-recreate
```

#### Memory Issues
```bash
# Check Docker memory
docker system df

# Clean up unused resources
./manage_docker.sh cleanup
docker system prune -a
```

#### Build Failures
```bash
# Clean build without cache
docker-compose build --no-cache

# Check logs
docker-compose logs <service-name>
```

### Debug Mode

Enable debug logging:

```bash
# Set debug environment
export COMPOSE_LOG_LEVEL=DEBUG

# Verbose output
./manage_docker.sh start --verbose
```

## 📚 Documentation

- [SSTI Scanner Main Documentation](../../../README.md)
- [Integration Test Guide](../README.md)
- [Template Engine Details](../../../CONTEXT.md)
- [API Documentation](../../../docs/API.md)

---

**Remember**: These applications are intentionally vulnerable and should only be used in isolated testing environments. Never deploy them in production or expose them to the internet.
