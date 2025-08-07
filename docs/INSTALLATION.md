# Installation Guide

This guide provides detailed instructions for installing and setting up the SSTI Scanner in various environments.

## Quick Installation

### From PyPI (Recommended)

```bash
pip install ssti-scanner
```

### From Source

```bash
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner
pip install -e .
```

## System Requirements

### Minimum Requirements

- **Python**: 3.8 or higher
- **Memory**: 512 MB RAM
- **Storage**: 100 MB free space
- **Network**: Internet connection for target scanning

### Recommended Requirements

- **Python**: 3.9 or higher
- **Memory**: 2 GB RAM
- **Storage**: 1 GB free space
- **CPU**: Multi-core processor for optimal performance

### Supported Operating Systems

- **Linux**: Ubuntu 18.04+, CentOS 7+, Debian 9+
- **macOS**: 10.14+ (Mojave and newer)
- **Windows**: Windows 10, Windows Server 2016+

## Installation Methods

### 1. PyPI Installation (Production)

The simplest way to install for regular use:

```bash
# Install latest stable version
pip install ssti-scanner

# Install specific version
pip install ssti-scanner==1.0.0

# Install with development dependencies
pip install ssti-scanner[dev]

# Install with all optional features
pip install ssti-scanner[all]
```

### 2. Source Installation (Development)

For development or to get the latest features:

```bash
# Clone repository
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e .[dev]
```

### 3. Docker Installation

Using Docker for isolated environments:

```bash
# Pull pre-built image
docker pull sstiscanner/ssti-scanner:latest

# Or build from source
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner
docker build -t ssti-scanner .

# Run scanner
docker run -it --rm ssti-scanner --help
```

### 4. Binary Installation

Download pre-compiled binaries from the [releases page](https://github.com/your-username/ssti-scanner/releases):

```bash
# Linux/macOS
wget https://github.com/your-username/ssti-scanner/releases/latest/download/ssti-scanner-linux
chmod +x ssti-scanner-linux
./ssti-scanner-linux --help

# Windows
# Download ssti-scanner-windows.exe from releases page
```

## Dependency Management

### Core Dependencies

The scanner requires these core packages:

```
aiohttp>=3.8.0          # Async HTTP client
beautifulsoup4>=4.10.0  # HTML parsing
pyyaml>=6.0             # Configuration files
lxml>=4.6.0             # XML parsing
urllib3>=1.26.0         # URL utilities
```

### Optional Dependencies

Additional features require optional packages:

```
# Development tools
pytest>=7.0.0           # Testing framework
pytest-asyncio>=0.20.0  # Async test support
pytest-mock>=3.6.0      # Mocking utilities
black>=22.0.0           # Code formatting
mypy>=0.950             # Type checking

# Reporting features
jinja2>=3.0.0           # HTML report templates
matplotlib>=3.5.0       # Charts and graphs
pandas>=1.4.0           # Data analysis

# Advanced features
selenium>=4.0.0         # Browser automation
requests-oauthlib>=1.3.0 # OAuth authentication
cryptography>=36.0.0    # Encryption utilities
```

### Installing Dependencies

```bash
# Install core dependencies only
pip install ssti-scanner

# Install with development tools
pip install ssti-scanner[dev]

# Install with reporting features
pip install ssti-scanner[reporting]

# Install with browser automation
pip install ssti-scanner[browser]

# Install everything
pip install ssti-scanner[all]
```

## Environment Setup

### Virtual Environment (Recommended)

Using virtual environments prevents dependency conflicts:

```bash
# Create virtual environment
python -m venv ssti-scanner-env

# Activate virtual environment
# On Linux/macOS:
source ssti-scanner-env/bin/activate

# On Windows:
ssti-scanner-env\Scripts\activate

# Install scanner
pip install ssti-scanner

# Deactivate when done
deactivate
```

### Conda Environment

Using Conda for package management:

```bash
# Create conda environment
conda create -n ssti-scanner python=3.9

# Activate environment
conda activate ssti-scanner

# Install scanner
pip install ssti-scanner

# Or install from conda-forge (if available)
conda install -c conda-forge ssti-scanner
```

### Poetry (Development)

Using Poetry for dependency management:

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Clone and setup project
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner

# Install dependencies
poetry install

# Activate shell
poetry shell

# Run scanner
ssti-scanner --help
```

## Platform-Specific Instructions

### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install system dependencies
sudo apt install build-essential libxml2-dev libxslt1-dev zlib1g-dev

# Install scanner
pip3 install ssti-scanner

# Verify installation
ssti-scanner --version
```

### CentOS/RHEL/Fedora

```bash
# Install Python and pip
sudo yum install python3 python3-pip  # CentOS 7
sudo dnf install python3 python3-pip  # CentOS 8+/Fedora

# Install development tools
sudo yum groupinstall "Development Tools"  # CentOS 7
sudo dnf groupinstall "Development Tools"  # CentOS 8+/Fedora

# Install XML libraries
sudo yum install libxml2-devel libxslt-devel  # CentOS 7
sudo dnf install libxml2-devel libxslt-devel  # CentOS 8+/Fedora

# Install scanner
pip3 install ssti-scanner
```

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3

# Install XML libraries
brew install libxml2 libxslt

# Install scanner
pip3 install ssti-scanner

# Add to PATH if needed
echo 'export PATH="/usr/local/opt/python/libexec/bin:$PATH"' >> ~/.zshrc
```

### Windows

#### Option 1: Windows Package Manager

```powershell
# Install Python via winget
winget install Python.Python.3.9

# Install scanner
pip install ssti-scanner
```

#### Option 2: Manual Installation

1. Download Python from [python.org](https://www.python.org/downloads/windows/)
2. Install Python (ensure "Add to PATH" is checked)
3. Open Command Prompt or PowerShell
4. Install scanner:

```cmd
pip install ssti-scanner
```

#### Option 3: Microsoft Store

1. Install Python from Microsoft Store
2. Open Command Prompt
3. Install scanner:

```cmd
pip install ssti-scanner
```

## Docker Setup

### Using Pre-built Image

```bash
# Pull latest image
docker pull sstiscanner/ssti-scanner:latest

# Run scanner
docker run --rm sstiscanner/ssti-scanner:latest --help

# Scan with Docker
docker run --rm sstiscanner/ssti-scanner:latest scan --url http://example.com

# Mount config files
docker run --rm -v $(pwd)/config:/app/config sstiscanner/ssti-scanner:latest scan --config /app/config/custom.yml --url http://example.com
```

### Building Custom Image

```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Install scanner
RUN pip install ssti-scanner

# Set working directory
WORKDIR /app

# Default command
ENTRYPOINT ["ssti-scanner"]
```

Build and run:

```bash
docker build -t my-ssti-scanner .
docker run --rm my-ssti-scanner --help
```

### Docker Compose

```yaml
version: '3.8'

services:
  ssti-scanner:
    image: sstiscanner/ssti-scanner:latest
    volumes:
      - ./config:/app/config
      - ./output:/app/output
    command: scan --config /app/config/scan.yml --output /app/output/results.json
    environment:
      - SSTI_DEBUG=1
```

Run with:

```bash
docker-compose run ssti-scanner scan --url http://example.com
```

## Cloud Platform Setup

### AWS EC2

```bash
# Launch EC2 instance (Amazon Linux 2)
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t3.micro

# Connect to instance
ssh -i your-key.pem ec2-user@your-instance-ip

# Install Python and scanner
sudo yum update -y
sudo yum install python3 python3-pip -y
pip3 install ssti-scanner

# Run scanner
ssti-scanner --help
```

### Google Cloud Platform

```bash
# Create VM instance
gcloud compute instances create ssti-scanner-vm \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=e2-micro

# SSH to instance
gcloud compute ssh ssti-scanner-vm

# Install scanner
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install ssti-scanner
```

### Azure

```bash
# Create VM
az vm create \
  --resource-group myResourceGroup \
  --name ssti-scanner-vm \
  --image UbuntuLTS \
  --size Standard_B1s

# SSH to VM
ssh azureuser@your-vm-ip

# Install scanner
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install ssti-scanner
```

## Verification

### Basic Verification

```bash
# Check installation
ssti-scanner --version
ssti-scanner --help

# Test basic functionality
ssti-scanner scan --url http://httpbin.org/get

# Run self-test
ssti-scanner test --self-check
```

### Comprehensive Testing

```bash
# Clone test repository (if developing)
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner

# Run test suite
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

## Troubleshooting

### Common Issues

#### 1. Python Version Error

```
Error: Python 3.8+ required
```

**Solution:**
```bash
# Check Python version
python --version
python3 --version

# Install newer Python version
# Ubuntu/Debian:
sudo apt install python3.9

# macOS:
brew install python@3.9

# Windows: Download from python.org
```

#### 2. Permission Denied

```
Error: Permission denied installing package
```

**Solution:**
```bash
# Use user installation
pip install --user ssti-scanner

# Or use virtual environment
python -m venv venv
source venv/bin/activate
pip install ssti-scanner
```

#### 3. SSL Certificate Error

```
Error: SSL certificate verification failed
```

**Solution:**
```bash
# Upgrade certificates
pip install --upgrade certifi

# Or bypass SSL (not recommended for production)
pip install --trusted-host pypi.org --trusted-host pypi.python.org ssti-scanner
```

#### 4. Binary Dependencies Missing

```
Error: Microsoft Visual C++ 14.0 is required (Windows)
Error: gcc not found (Linux)
```

**Solution:**

**Windows:**
- Install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install build-essential

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
```

#### 5. Memory Error

```
MemoryError: Unable to allocate memory
```

**Solution:**
```bash
# Reduce thread count
ssti-scanner scan --threads 2 --url http://example.com

# Use Docker with memory limit
docker run --memory=512m sstiscanner/ssti-scanner scan --url http://example.com
```

### Getting Help

1. **Check Documentation**: [docs/](docs/)
2. **Search Issues**: [GitHub Issues](https://github.com/samir-djili/ssti-scanner/issues)
3. **Ask Questions**: [Discussions](https://github.com/samir-djili/ssti-scanner/discussions)
4. **Report Bugs**: [New Issue](https://github.com/samir-djili/ssti-scanner/issues/new)

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Enable debug logging
ssti-scanner --debug scan --url http://example.com

# Save debug log to file
ssti-scanner --debug scan --url http://example.com 2> debug.log

# Environment variable
export SSTI_DEBUG=1
ssti-scanner scan --url http://example.com
```

## Next Steps

After successful installation:

1. **Read the [CLI Guide](CLI_GUIDE.md)** for command-line usage
2. **Check [Examples](../examples/)** for practical usage patterns
3. **Review [API Documentation](API.md)** for programmatic usage
4. **Configure the scanner** with [Configuration Guide](CONFIGURATION.md)

## Uninstallation

### Remove Package

```bash
# Remove scanner
pip uninstall ssti-scanner

# Remove all dependencies (be careful)
pip freeze | grep -v "^-e" | xargs pip uninstall -y

# Remove virtual environment
rm -rf ssti-scanner-env
```

### Remove Docker

```bash
# Remove images
docker rmi sstiscanner/ssti-scanner:latest

# Remove containers
docker container prune

# Remove volumes
docker volume prune
```

## License

This installation guide is part of the SSTI Scanner project, licensed under the MIT License. See [LICENSE](../LICENSE) for details.
