
#!/bin/bash

# BlackDeD Advanced Startup Script
# Comprehensive auto-setup, dependency management, and issue resolution

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Logging functions
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${BOLD}${BLUE}$1${NC}"
}

# Banner function
show_banner() {
    clear
    echo -e "${GREEN}${BOLD}"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    echo "│                         BlackDeD Auto-Startup Script                       │"
    echo "│                    Advanced Dependency Management & Auto-Fix               │"
    echo "├─────────────────────────────────────────────────────────────────────────────┤"
    echo "│  🔧 Auto-dependency resolution     🛠️  System optimization                │"
    echo "│  🔍 Environment validation         ⚡ Performance enhancements            │"
    echo "│  🚀 Automatic tool launch          🛡️  Security configurations            │"
    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

# System information gathering
check_system_info() {
    log_header "📊 SYSTEM INFORMATION GATHERING"
    
    log_info "Detecting system environment..."
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="Linux"
        if [ -f /etc/os-release ]; then
            DISTRO=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
            VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
            log_info "Detected: $DISTRO $VERSION"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        log_info "Detected: macOS"
    else
        OS="Unknown"
        log_warning "Unknown OS detected: $OSTYPE"
    fi
    
    # Check if running in Replit
    if [ -n "$REPL_ID" ] || [ -n "$REPLIT_ENVIRONMENT" ] || [ -d "/nix" ]; then
        ENVIRONMENT="Replit"
        log_success "Running in Replit environment"
    elif [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
        ENVIRONMENT="Termux"
        log_success "Running in Termux environment"
    else
        ENVIRONMENT="Standard"
        log_info "Running in standard environment"
    fi
    
    # System resources
    MEMORY_GB=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "N/A")
    CPU_CORES=$(nproc 2>/dev/null || echo "N/A")
    
    log_info "Memory: $MEMORY_GB | CPU Cores: $CPU_CORES | Environment: $ENVIRONMENT"
    echo
}

# Python environment validation and setup
setup_python_environment() {
    log_header "🐍 PYTHON ENVIRONMENT SETUP"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log_success "Python3 detected: $PYTHON_VERSION"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version | cut -d' ' -f2)
        log_success "Python detected: $PYTHON_VERSION"
        PYTHON_CMD="python"
    else
        log_error "Python not found! Attempting installation..."
        install_python
    fi
    
    # Validate Python version (require 3.8+)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        log_error "Python 3.8+ required. Current version: $PYTHON_VERSION"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_warning "pip not found! Installing pip..."
        install_pip
    fi
    
    # Upgrade pip
    log_info "Upgrading pip to latest version..."
    $PYTHON_CMD -m pip install --upgrade pip &>/dev/null || true
    
    echo
}

# Install Python if not present
install_python() {
    if [ "$ENVIRONMENT" = "Replit" ]; then
        log_info "Python should be available in Replit environment"
        exit 1
    elif [ "$ENVIRONMENT" = "Termux" ]; then
        log_info "Installing Python in Termux..."
        pkg update && pkg install python
    elif [ "$OS" = "Linux" ]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3 python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v pacman &> /dev/null; then
            sudo pacman -S python python-pip
        fi
    fi
}

# Install pip if not present
install_pip() {
    log_info "Installing pip..."
    if command -v curl &> /dev/null; then
        curl https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
    elif command -v wget &> /dev/null; then
        wget -O - https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
    fi
}

# System dependencies validation and installation
install_system_dependencies() {
    log_header "📦 SYSTEM DEPENDENCIES INSTALLATION"
    
    # Required system packages
    REQUIRED_PACKAGES=("nmap" "tcpdump" "file")
    
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            log_warning "$package not found. Attempting installation..."
            install_system_package "$package"
        else
            log_success "$package is available"
        fi
    done
    
    echo
}

# Install system package based on environment
install_system_package() {
    local package=$1
    
    if [ "$ENVIRONMENT" = "Replit" ]; then
        log_info "$package should be available in Replit Nix environment"
    elif [ "$ENVIRONMENT" = "Termux" ]; then
        log_info "Installing $package in Termux..."
        pkg install "$package" 2>/dev/null || log_warning "Failed to install $package"
    elif [ "$OS" = "Linux" ]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y "$package" 2>/dev/null || log_warning "Failed to install $package"
        elif command -v yum &> /dev/null; then
            sudo yum install -y "$package" 2>/dev/null || log_warning "Failed to install $package"
        elif command -v pacman &> /dev/null; then
            sudo pacman -S "$package" 2>/dev/null || log_warning "Failed to install $package"
        fi
    fi
}

# Python dependencies installation with smart resolution
install_python_dependencies() {
    log_header "📚 PYTHON DEPENDENCIES INSTALLATION"
    
    # Check if requirements.txt exists
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found!"
        exit 1
    fi
    
    log_info "Installing Python dependencies from requirements.txt..."
    
    # Create a backup of current environment
    log_info "Creating dependency backup..."
    $PYTHON_CMD -m pip freeze > requirements_backup.txt 2>/dev/null || true
    
    # Install with retries and conflict resolution
    install_with_retries() {
        local attempt=1
        local max_attempts=3
        
        while [ $attempt -le $max_attempts ]; do
            log_info "Installation attempt $attempt/$max_attempts..."
            
            if $PYTHON_CMD -m pip install -r requirements.txt --upgrade 2>/dev/null; then
                log_success "Dependencies installed successfully!"
                return 0
            else
                log_warning "Installation attempt $attempt failed"
                
                if [ $attempt -eq $max_attempts ]; then
                    log_error "All installation attempts failed. Trying individual packages..."
                    install_packages_individually
                    return $?
                fi
                
                # Try to resolve conflicts
                log_info "Attempting to resolve conflicts..."
                $PYTHON_CMD -m pip install --upgrade pip setuptools wheel 2>/dev/null || true
                
                attempt=$((attempt + 1))
                sleep 2
            fi
        done
    }
    
    # Install packages individually if bulk install fails
    install_packages_individually() {
        log_info "Installing packages individually..."
        local failed_packages=()
        
        while IFS= read -r line; do
            # Skip empty lines and comments
            [[ -z "$line" || "$line" =~ ^#.* ]] && continue
            
            # Extract package name
            package=$(echo "$line" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 | cut -d'!' -f1)
            
            log_info "Installing $package..."
            if ! $PYTHON_CMD -m pip install "$line" 2>/dev/null; then
                log_warning "Failed to install $package"
                failed_packages+=("$package")
            else
                log_success "Installed $package"
            fi
        done < requirements.txt
        
        if [ ${#failed_packages[@]} -gt 0 ]; then
            log_warning "Failed to install: ${failed_packages[*]}"
            log_info "Continuing with available packages..."
        fi
    }
    
    install_with_retries
    echo
}

# Remove problematic packages
clean_problematic_packages() {
    log_header "🧹 CLEANING PROBLEMATIC PACKAGES"
    
    # List of potentially problematic packages
    PROBLEMATIC_PACKAGES=("rust" "rustc" "cargo")
    
    for package in "${PROBLEMATIC_PACKAGES[@]}"; do
        if command -v "$package" &> /dev/null; then
            log_info "Found $package - checking if it's causing issues..."
            # In Replit, these are managed by Nix, so we don't remove them
            if [ "$ENVIRONMENT" != "Replit" ]; then
                log_warning "Consider removing $package if experiencing stability issues"
            fi
        fi
    done
    
    # Clean pip cache
    log_info "Cleaning pip cache..."
    $PYTHON_CMD -m pip cache purge 2>/dev/null || true
    
    # Clean Python bytecode
    log_info "Cleaning Python bytecode files..."
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    
    echo
}

# Environment optimization
optimize_environment() {
    log_header "⚡ ENVIRONMENT OPTIMIZATION"
    
    # Set Python optimizations
    export PYTHONUNBUFFERED=1
    export PYTHONDONTWRITEBYTECODE=1
    
    # Set locale if not set
    if [ -z "$LC_ALL" ]; then
        export LC_ALL=C.UTF-8
        export LANG=C.UTF-8
    fi
    
    # Increase file descriptor limits if possible
    ulimit -n 4096 2>/dev/null || true
    
    # Set optimal Python path
    export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$(pwd)"
    
    log_success "Environment optimized"
    echo
}

# Security configurations
setup_security() {
    log_header "🛡️ SECURITY CONFIGURATIONS"
    
    # Set secure permissions on sensitive files
    chmod 600 *.py 2>/dev/null || true
    
    # Check for secure random generation
    if $PYTHON_CMD -c "import secrets; print('OK')" 2>/dev/null; then
        log_success "Secure random generation available"
    else
        log_warning "Secure random generation may not be available"
    fi
    
    # Validate SSL/TLS support
    if $PYTHON_CMD -c "import ssl; print('OK')" 2>/dev/null; then
        log_success "SSL/TLS support available"
    else
        log_warning "SSL/TLS support may be limited"
    fi
    
    echo
}

# Validate BlackDeD installation
validate_blackded() {
    log_header "🔍 BLACKDED VALIDATION"
    
    # Check main files
    REQUIRED_FILES=("main.py" "crypto_tools.py" "osint_tools.py" "web_scanner.py" "requirements.txt")
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$file" ]; then
            log_success "$file found"
        else
            log_error "$file missing!"
            exit 1
        fi
    done
    
    # Test Python imports
    log_info "Testing Python imports..."
    if $PYTHON_CMD -c "
import sys
try:
    import colorama
    import requests
    import rich
    import pyfiglet
    print('Core imports: OK')
except ImportError as e:
    print(f'Import error: {e}')
    sys.exit(1)
" 2>/dev/null; then
        log_success "Core Python imports working"
    else
        log_error "Python import issues detected!"
        exit 1
    fi
    
    echo
}

# Performance monitoring setup
setup_monitoring() {
    log_header "📊 PERFORMANCE MONITORING SETUP"
    
    # Create monitoring script
    cat > monitor.py << 'EOF'
#!/usr/bin/env python3
import psutil
import time
import sys

def monitor_resources():
    """Monitor system resources"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        print(f"CPU Usage: {cpu_percent}%")
        print(f"Memory Usage: {memory.percent}% ({memory.used // 1024 // 1024}MB / {memory.total // 1024 // 1024}MB)")
        
        if cpu_percent > 90:
            print("WARNING: High CPU usage detected!")
        if memory.percent > 90:
            print("WARNING: High memory usage detected!")
            
    except Exception as e:
        print(f"Monitoring error: {e}")

if __name__ == "__main__":
    monitor_resources()
EOF
    
    chmod +x monitor.py
    log_success "Performance monitoring setup complete"
    echo
}

# Network connectivity check
check_network() {
    log_header "🌐 NETWORK CONNECTIVITY CHECK"
    
    # Test basic connectivity
    if ping -c 1 8.8.8.8 &>/dev/null; then
        log_success "Internet connectivity: OK"
    else
        log_warning "Limited internet connectivity"
    fi
    
    # Test DNS resolution
    if nslookup google.com &>/dev/null; then
        log_success "DNS resolution: OK"
    else
        log_warning "DNS resolution issues"
    fi
    
    echo
}

# Create recovery script
create_recovery_script() {
    log_header "🚑 CREATING RECOVERY SCRIPT"
    
    cat > recovery.sh << 'EOF'
#!/bin/bash
echo "BlackDeD Recovery Script"
echo "========================"

# Kill any hanging processes
pkill -f "python.*main.py" 2>/dev/null || true
pkill -f "BlackDeD" 2>/dev/null || true

# Clean temporary files
rm -rf __pycache__ *.pyc .pytest_cache 2>/dev/null || true

# Reset environment
unset PYTHONPATH
export PYTHONUNBUFFERED=1

# Restart with clean environment
echo "Restarting BlackDeD with clean environment..."
exec ./start.sh
EOF
    
    chmod +x recovery.sh
    log_success "Recovery script created (./recovery.sh)"
    echo
}

# Launch BlackDeD
launch_blackded() {
    log_header "🚀 LAUNCHING BLACKDED"
    
    log_info "Starting BlackDeD Advanced Ethical Hacking Toolkit..."
    
    # Final environment check
    log_info "Final environment validation..."
    $PYTHON_CMD -c "
import sys
print(f'Python: {sys.version}')
print(f'Platform: {sys.platform}')
print(f'Executable: {sys.executable}')
" 2>/dev/null || true
    
    # Launch with proper error handling
    log_success "Launching BlackDeD..."
    echo -e "${GREEN}${BOLD}"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    echo "│                          BlackDeD is starting...                           │"
    echo "│                     Use Ctrl+C to stop the application                     │"
    echo "│                   Use ./recovery.sh if issues occur                        │"
    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
    
    sleep 2
    
    # Execute BlackDeD
    exec $PYTHON_CMD main.py
}

# Error handling
handle_error() {
    log_error "An error occurred during setup!"
    log_info "Recovery options:"
    log_info "1. Run './recovery.sh' to reset environment"
    log_info "2. Check './start.sh' for manual debugging"
    log_info "3. Verify requirements.txt and dependencies"
    exit 1
}

# Trap errors
trap handle_error ERR

# Main execution flow
main() {
    show_banner
    
    log_header "🔧 BLACKDED ADVANCED STARTUP SEQUENCE"
    echo
    
    check_system_info
    setup_python_environment
    install_system_dependencies
    clean_problematic_packages
    install_python_dependencies
    optimize_environment
    setup_security
    validate_blackded
    setup_monitoring
    check_network
    create_recovery_script
    
    log_header "✅ SETUP COMPLETE"
    log_success "All systems ready! Launching BlackDeD..."
    echo
    
    launch_blackded
}

# Execute main function
main "$@"
