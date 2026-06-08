#!/bin/bash

###############################################################################
# security/scripts/generate-sbom.sh
#
# SBOM Generation Workflow - Phase 1
#
# Purpose:
#   Automatically discover Docker images and generate Software
#   Bill of Materials (SBOM) using Syft for each image.
#
# Output:
#   - CycloneDX JSON format SBOMs
#   - Human-readable Markdown summaries
#   - All files saved to: security/reports/sbom/
#
# Usage:
#   bash ./security/scripts/generate-sbom.sh
#
# Requirements:
#   - Docker daemon running
#   - Syft installed (auto-installed if missing)
#   - jq for JSON parsing
#   - User has docker access (membership in docker group)
#
###############################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SBOM_OUTPUT_DIR="${PROJECT_ROOT}/security/reports/sbom"
TIMESTAMP=$(date +%Y-%m-%d)

# ═══════════════════════════════════════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}ℹ️  $*${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $*${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠️  $*${NC}"
}

log_error() {
    echo -e "${RED}✗ $*${NC}" >&2
}

# Create safe filename from image name
make_filename_safe() {
    local name="$1"
    # Replace problematic characters with underscores
    # This handles slashes and colons in image names
    echo "$name" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

# Check if Syft is installed, install if missing
ensure_syft() {
    if command -v syft &> /dev/null; then
        log_success "Syft is installed"
        syft version 2>/dev/null | head -1 || true
        return 0
    fi
    
    log_warn "Syft not found, installing..."
    
    # Detect OS and install Syft
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            log_info "Installing Syft via apt..."
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        elif command -v yum &> /dev/null; then
            log_info "Installing Syft via yum..."
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        else
            log_error "Unsupported package manager. Please install Syft manually from https://github.com/anchore/syft"
            return 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            log_info "Installing Syft via Homebrew..."
            brew install syft
        else
            log_error "Homebrew not found. Please install Syft manually from https://github.com/anchore/syft"
            return 1
        fi
    else
        log_error "Unsupported OS. Please install Syft manually from https://github.com/anchore/syft"
        return 1
    fi
    
    if command -v syft &> /dev/null; then
        log_success "Syft installed successfully"
        return 0
    else
        log_error "Syft installation failed"
        return 1
    fi
}

# Check if jq is installed
check_jq() {
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        log_info "Install jq using: apt-get install jq (Linux) or brew install jq (macOS)"
        return 1
    fi
    return 0
}

# Generate Markdown summary from CycloneDX JSON
generate_markdown_report() {
    local image_name="$1"
    local json_file="$2"
    local safe_name="$3"
    local md_file="${SBOM_OUTPUT_DIR}/${safe_name}-${TIMESTAMP}.md"
    
    if [[ ! -f "$json_file" ]]; then
        log_error "JSON file not found: $json_file"
        return 1
    fi
    
    # Extract metadata from JSON
    local spec_version json_version component_version total_packages
    
    spec_version=$(jq -r '.specVersion // "1.5"' "$json_file")
    total_packages=$(jq '.components // [] | length' "$json_file")
    
    # Start building markdown file with printf to avoid heredoc stdin issues
    {
        printf "# SBOM Report: %s\n\n" "$image_name"
        printf "**Generated:** %s\n\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf "**Container Image:** \\\`%s\\\`\n\n" "$image_name"
        printf "**CycloneDX Spec Version:** %s\n\n" "$spec_version"
        printf "**Total Packages:** %s\n\n" "$total_packages"
        printf "## Packages\n\n"
        printf "| Package Name | Version | Type |\n"
        printf "|--------------|---------|------|\n"
        
        # Extract and sort packages using only jq and sed - no while loops
        jq -r '.components[]? | "\(.name)|\(.version)|\(.type)"' "$json_file" | \
            sort -t '|' -k 1 | \
            sed 's/\([^|]*\)|\([^|]*\)|\(.*\)/| `\1` | \2 | \3 |/'
        
        printf "\n---\n\n"
        printf "_Report generated by security/scripts/generate-sbom.sh_\n"
    } > "$md_file"
    
    log_success "Generated Markdown report: $md_file"
}

# Generate SBOM for a single Docker image
generate_sbom_for_image() {
    local image_name="$1"
    local safe_name
    local json_file
    
    # Use the sanitized image name as filename
    safe_name=$(make_filename_safe "$image_name")
    json_file="${SBOM_OUTPUT_DIR}/${safe_name}-${TIMESTAMP}.cdx.json"
    
    log_info "Scanning image: $image_name"
    
    # Generate CycloneDX JSON with timeout (120 seconds per image)
    # Use explicit conditional to handle set -euo pipefail safely
    if timeout 120 syft "$image_name" -o cyclonedx-json > "$json_file" 2>/dev/null; then
        log_success "Generated SBOM JSON: $json_file"
        
        # Generate Markdown report
        if ! generate_markdown_report "$image_name" "$json_file" "$safe_name"; then
            log_error "Failed to generate Markdown report for $image_name"
            return 1
        fi
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "Timeout scanning $image_name (exceeded 120 seconds)"
        else
            log_error "Failed to generate SBOM for $image_name (exit code: $exit_code)"
        fi
        rm -f "$json_file"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Workflow
# ═══════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                 SBOM Generation Workflow - Phase 1                  ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Verify prerequisites
    log_info "Verifying prerequisites..."
    ensure_syft || exit 1
    check_jq || exit 1
    
    # Create output directory
    if [[ ! -d "$SBOM_OUTPUT_DIR" ]]; then
        log_info "Creating output directory: $SBOM_OUTPUT_DIR"
        mkdir -p "$SBOM_OUTPUT_DIR"
    fi
    
    log_success "Output directory ready: $SBOM_OUTPUT_DIR"
    
    # Discover Docker images
    log_info "Discovering Docker images..."
    local images
    images=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null || echo "")
    
    if [[ -z "$images" ]]; then
        log_warn "No Docker images found"
        echo ""
        return 0
    fi
    
    local image_count
    image_count=$(echo "$images" | grep -v '^:$' | wc -l)
    log_success "Found $image_count Docker image(s)"
    echo ""
    
    # Process each image
    local failed_count=0
    local success_count=0
    
    local image_num=0
    while IFS= read -r image_name; do
        # Skip empty lines and dangling images (entries with just ":")
        if [[ -z "$image_name" ]] || [[ "$image_name" == ":" ]]; then
            continue
        fi
        
        ((++image_num))
        
        if generate_sbom_for_image "$image_name"; then
            ((++success_count))
        else
            ((++failed_count))
        fi
        echo ""
    done <<< "$images"
    
    echo "DEBUG: Processed $image_num images (success: $success_count, failed: $failed_count)" >&2
    
    # Summary
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                              Summary                               ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    log_success "Generated SBOMs: $success_count"
    
    if [[ $failed_count -gt 0 ]]; then
        log_warn "Failed SBOMs: $failed_count"
    fi
    
    echo ""
    log_info "Output directory: $SBOM_OUTPUT_DIR"
    echo ""
    
    # List generated files
    if [[ -d "$SBOM_OUTPUT_DIR" ]]; then
        local file_count
        file_count=$(find "$SBOM_OUTPUT_DIR" -type f | wc -l)
        if [[ $file_count -gt 0 ]]; then
            echo "Generated files:"
            find "$SBOM_OUTPUT_DIR" -type f -printf "  • %f\n" | sort
        fi
    fi
    
    echo ""
    
    # Exit with appropriate code
    if [[ $failed_count -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Run main function
main "$@"
