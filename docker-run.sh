#!/bin/bash

# AutoSecScan Docker Build and Run Script
# This script builds the Docker image and provides easy command shortcuts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

IMAGE_NAME="autosecscan"
IMAGE_TAG="latest"

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to build the Docker image
build_image() {
    print_info "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
    docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
    
    if [ $? -eq 0 ]; then
        print_info "Docker image built successfully!"
        docker images | grep ${IMAGE_NAME}
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# Function to run a scan
run_scan() {
    local target=$1
    local extra_args="${@:2}"
    
    if [ -z "$target" ]; then
        print_error "No target URL provided"
        echo "Usage: $0 scan <URL> [additional flags]"
        exit 1
    fi
    
    print_info "Scanning target: $target"
    
    # Create reports directory if it doesn't exist
    mkdir -p reports
    
    docker run --rm \
        -v "$(pwd)/reports:/app/reports" \
        ${IMAGE_NAME}:${IMAGE_TAG} \
        $target $extra_args
}

# Function to run interactive shell
run_shell() {
    print_info "Starting interactive shell in container"
    docker run --rm -it \
        -v "$(pwd)/reports:/app/reports" \
        --entrypoint /bin/sh \
        ${IMAGE_NAME}:${IMAGE_TAG}
}

# Function to show help
show_help() {
    cat << EOF
AutoSecScan Docker Helper Script

Usage:
    $0 <command> [options]

Commands:
    build               Build the Docker image
    scan <URL> [flags]  Run a security scan on target URL
    shell               Start interactive shell in container
    help                Show this help message

Examples:
    # Build the image
    $0 build

    # Run a basic scan
    $0 scan https://example.com

    # Run scan with custom options
    $0 scan https://example.com --output both --skip nmap

    # Run scan with verbose output
    $0 scan https://example.com --verbose

    # Start interactive shell
    $0 shell

Docker Compose:
    # Build using docker-compose
    docker-compose build

    # Run a scan
    docker-compose run --rm autosecscan https://example.com

    # Run with options
    docker-compose run --rm autosecscan https://example.com --output html

Direct Docker:
    # Pull image (if available)
    docker pull ${IMAGE_NAME}:${IMAGE_TAG}

    # Run container
    docker run --rm -v \$(pwd)/reports:/app/reports ${IMAGE_NAME}:${IMAGE_TAG} https://example.com

EOF
}

# Main script logic
case "$1" in
    build)
        build_image
        ;;
    scan)
        run_scan "${@:2}"
        ;;
    shell)
        run_shell
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
