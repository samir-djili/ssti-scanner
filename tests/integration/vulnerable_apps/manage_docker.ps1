# SSTI Scanner - Vulnerable Applications Docker Manager (PowerShell)
# This script manages Docker containers for SSTI testing applications

param(
    [Parameter(Position=0)]
    [ValidateSet('build', 'start', 'stop', 'restart', 'status', 'logs', 'health', 'test', 'cleanup', 'help')]
    [string]$Command = 'help',
    
    [Parameter(Position=1)]
    [string]$Service = ''
)

# Configuration
$ComposeFile = "docker-compose.yml"
$ProjectName = "ssti-scanner-test"
$NetworkName = "ssti-test-network"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to check if Docker is running
function Test-Docker {
    try {
        docker info 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker is running"
            return $true
        }
    }
    catch {
        Write-Error "Docker is not running. Please start Docker and try again."
        exit 1
    }
    return $false
}

# Function to check if Docker Compose is available
function Test-DockerCompose {
    try {
        docker-compose --version 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose is available"
            return $true
        }
    }
    catch {
        Write-Error "Docker Compose is not installed. Please install it and try again."
        exit 1
    }
    return $false
}

# Function to build all images
function Build-Images {
    Write-Status "Building all vulnerable application images..."
    docker-compose -p $ProjectName -f $ComposeFile build
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All images built successfully"
    } else {
        Write-Error "Failed to build images"
        exit 1
    }
}

# Function to start all services
function Start-Services {
    Write-Status "Starting all vulnerable application services..."
    docker-compose -p $ProjectName -f $ComposeFile up -d
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All services started successfully"
    } else {
        Write-Error "Failed to start services"
        exit 1
    }
}

# Function to stop all services
function Stop-Services {
    Write-Status "Stopping all vulnerable application services..."
    docker-compose -p $ProjectName -f $ComposeFile down
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All services stopped successfully"
    } else {
        Write-Error "Failed to stop services"
    }
}

# Function to restart all services
function Restart-Services {
    Write-Status "Restarting all vulnerable application services..."
    Stop-Services
    Start-Services
}

# Function to show service status
function Show-Status {
    Write-Status "Checking service status..."
    docker-compose -p $ProjectName -f $ComposeFile ps
}

# Function to show service logs
function Show-Logs {
    param([string]$ServiceName)
    
    if ($ServiceName) {
        Write-Status "Showing logs for service: $ServiceName"
        docker-compose -p $ProjectName -f $ComposeFile logs -f $ServiceName
    } else {
        Write-Status "Showing logs for all services..."
        docker-compose -p $ProjectName -f $ComposeFile logs -f
    }
}

# Function to clean up everything
function Invoke-Cleanup {
    Write-Status "Cleaning up containers, networks, and volumes..."
    docker-compose -p $ProjectName -f $ComposeFile down -v --remove-orphans
    
    # Remove any dangling images
    $danglingImages = docker images -f "dangling=true" -q
    if ($danglingImages) {
        Write-Status "Removing dangling images..."
        docker rmi $danglingImages
    }
    
    Write-Success "Cleanup completed"
}

# Function to run health checks
function Test-Health {
    Write-Status "Running health checks on all services..."
    
    $services = @(
        @{name="jinja2-flask"; port=5000},
        @{name="django-templates"; port=8000},
        @{name="twig-symfony"; port=8001},
        @{name="smarty"; port=8002},
        @{name="freemarker-spring"; port=8080}
    )
    
    foreach ($service in $services) {
        $name = $service.name
        $port = $service.port
        
        Write-Status "Checking $name on port $port..."
        
        # Wait for service to be ready
        $timeout = 60
        $counter = 0
        $healthy = $false
        
        while ($counter -lt $timeout) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:$port/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    Write-Success "$name is healthy"
                    $healthy = $true
                    break
                }
            }
            catch {
                # Ignore errors and continue checking
            }
            Start-Sleep -Seconds 1
            $counter++
        }
        
        if (-not $healthy) {
            Write-Warning "$name health check timed out"
        }
    }
}

# Function to run integration tests
function Invoke-Tests {
    Write-Status "Running SSTI scanner against vulnerable applications..."
    
    # Ensure services are running
    $runningServices = docker-compose -p $ProjectName -f $ComposeFile ps -q
    if (-not $runningServices) {
        Write-Warning "Services are not running. Starting them first..."
        Start-Services
        Start-Sleep -Seconds 10
        Test-Health
    }
    
    # Run the actual tests
    Write-Status "Executing integration tests..."
    Push-Location
    Set-Location "../../.."
    python -m pytest tests/integration/ -v --tb=short
    Pop-Location
    
    Write-Success "Integration tests completed"
}

# Function to display help
function Show-Help {
    Write-Host "SSTI Scanner - Vulnerable Applications Docker Manager" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: .\manage_docker.ps1 [COMMAND] [SERVICE]" -ForegroundColor White
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  build       Build all Docker images" -ForegroundColor White
    Write-Host "  start       Start all services" -ForegroundColor White
    Write-Host "  stop        Stop all services" -ForegroundColor White
    Write-Host "  restart     Restart all services" -ForegroundColor White
    Write-Host "  status      Show service status" -ForegroundColor White
    Write-Host "  logs [svc]  Show logs (optionally for specific service)" -ForegroundColor White
    Write-Host "  health      Run health checks on all services" -ForegroundColor White
    Write-Host "  test        Run integration tests against applications" -ForegroundColor White
    Write-Host "  cleanup     Stop services and clean up resources" -ForegroundColor White
    Write-Host "  help        Show this help message" -ForegroundColor White
    Write-Host ""
    Write-Host "Available services:" -ForegroundColor Yellow
    Write-Host "  - jinja2-flask     (Flask with Jinja2)      http://localhost:5000" -ForegroundColor White
    Write-Host "  - django-templates (Django Templates)       http://localhost:8000" -ForegroundColor White
    Write-Host "  - twig-symfony     (Symfony with Twig)      http://localhost:8001" -ForegroundColor White
    Write-Host "  - smarty           (PHP with Smarty)        http://localhost:8002" -ForegroundColor White
    Write-Host "  - freemarker-spring(Spring with FreeMarker) http://localhost:8080" -ForegroundColor White
}

# Main script logic
function Main {
    # Check prerequisites
    if (-not (Test-Docker)) { exit 1 }
    if (-not (Test-DockerCompose)) { exit 1 }
    
    # Change to script directory
    Set-Location $PSScriptRoot
    
    switch ($Command.ToLower()) {
        'build' {
            Build-Images
        }
        'start' {
            Start-Services
            Start-Sleep -Seconds 5
            Test-Health
        }
        'stop' {
            Stop-Services
        }
        'restart' {
            Restart-Services
            Start-Sleep -Seconds 5
            Test-Health
        }
        'status' {
            Show-Status
        }
        'logs' {
            Show-Logs -ServiceName $Service
        }
        'health' {
            Test-Health
        }
        'test' {
            Invoke-Tests
        }
        'cleanup' {
            Invoke-Cleanup
        }
        'help' {
            Show-Help
        }
        default {
            Write-Error "Unknown command: $Command"
            Write-Host ""
            Show-Help
            exit 1
        }
    }
}

# Run main function
Main
