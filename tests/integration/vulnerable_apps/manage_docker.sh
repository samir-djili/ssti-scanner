#!/bin/bash

# SSTI Scanner - Vulnerable Applications Docker Manager
# This script manages Docker containers for SSTI testing applications

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
PROJECT_NAME="ssti-scanner-test"
NETWORK_NAME="ssti-test-network"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose >/dev/null 2>&1; then
        print_error "Docker Compose is not installed. Please install it and try again."
        exit 1
    fi
    print_success "Docker Compose is available"
}

# Function to build all images
build_images() {
    print_status "Building all vulnerable application images..."
    docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE build
    print_success "All images built successfully"
}

# Function to start all services
start_services() {
    print_status "Starting all vulnerable application services..."
    docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE up -d
    print_success "All services started successfully"
}

# Function to stop all services
stop_services() {
    print_status "Stopping all vulnerable application services..."
    docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE down
    print_success "All services stopped successfully"
}

# Function to restart all services
restart_services() {
    print_status "Restarting all vulnerable application services..."
    stop_services
    start_services
}

# Function to show service status
show_status() {
    print_status "Checking service status..."
    docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE ps
}

# Function to show service logs
show_logs() {
    if [ -n "$1" ]; then
        print_status "Showing logs for service: $1"
        docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE logs -f "$1"
    else
        print_status "Showing logs for all services..."
        docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE logs -f
    fi
}

# Function to clean up everything
cleanup() {
    print_status "Cleaning up containers, networks, and volumes..."
    docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE down -v --remove-orphans
    
    # Remove any dangling images
    if [ "$(docker images -f "dangling=true" -q)" ]; then
        print_status "Removing dangling images..."
        docker rmi $(docker images -f "dangling=true" -q)
    fi
    
    print_success "Cleanup completed"
}

# Function to run health checks
health_check() {
    print_status "Running health checks on all services..."
    
    services=("jinja2-flask:5000" "django-templates:8000" "twig-symfony:8001" "smarty:8002" "freemarker-spring:8080")
    
    for service in "${services[@]}"; do
        IFS=':' read -ra ADDR <<< "$service"
        name="${ADDR[0]}"
        port="${ADDR[1]}"
        
        print_status "Checking $name on port $port..."
        
        # Wait for service to be ready
        timeout=60
        counter=0
        while [ $counter -lt $timeout ]; do
            if curl -f -s "http://localhost:$port/health" >/dev/null 2>&1; then
                print_success "$name is healthy"
                break
            fi
            sleep 1
            counter=$((counter + 1))
        done
        
        if [ $counter -eq $timeout ]; then
            print_warning "$name health check timed out"
        fi
    done
}

# Function to run integration tests
run_tests() {
    print_status "Running SSTI scanner against vulnerable applications..."
    
    # Ensure services are running
    if ! docker-compose -p $PROJECT_NAME -f $COMPOSE_FILE ps | grep -q "Up"; then
        print_warning "Services are not running. Starting them first..."
        start_services
        sleep 10
        health_check
    fi
    
    # Run the actual tests
    print_status "Executing integration tests..."
    cd ../../..
    python -m pytest tests/integration/ -v --tb=short
    cd tests/integration/vulnerable_apps
    
    print_success "Integration tests completed"
}

# Function to display help
show_help() {
    echo "SSTI Scanner - Vulnerable Applications Docker Manager"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build       Build all Docker images"
    echo "  start       Start all services"
    echo "  stop        Stop all services"
    echo "  restart     Restart all services"
    echo "  status      Show service status"
    echo "  logs [svc]  Show logs (optionally for specific service)"
    echo "  health      Run health checks on all services"
    echo "  test        Run integration tests against applications"
    echo "  cleanup     Stop services and clean up resources"
    echo "  help        Show this help message"
    echo ""
    echo "Available services:"
    echo "  - jinja2-flask     (Flask with Jinja2)      http://localhost:5000"
    echo "  - django-templates (Django Templates)       http://localhost:8000"
    echo "  - twig-symfony     (Symfony with Twig)      http://localhost:8001"
    echo "  - smarty           (PHP with Smarty)        http://localhost:8002"
    echo "  - freemarker-spring(Spring with FreeMarker) http://localhost:8080"
}

# Main script logic
main() {
    # Check prerequisites
    check_docker
    check_docker_compose
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    case "${1:-help}" in
        build)
            build_images
            ;;
        start)
            start_services
            sleep 5
            health_check
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            sleep 5
            health_check
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "$2"
            ;;
        health)
            health_check
            ;;
        test)
            run_tests
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
