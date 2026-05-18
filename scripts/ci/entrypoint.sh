#!/bin/bash
# ==============================================================================
# APPredator GitHub Action Entrypoint
# ==============================================================================
# This script handles the initialization and execution of the security scan
# within the Docker environment. It manages path resolution between the
# GitHub Runner Workspace and the Docker Container filesystem.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Function to log messages with timestamps
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1"
}

# CRITICAL FIX: Unset JAVA_HOME from host to let Docker use its own JDK
# GitHub Actions runner injects /opt/hostedtoolcache/... which breaks JADX in container
if [ -n "$JAVA_HOME" ]; then
    unset JAVA_HOME
fi

# Re-define internal JAVA_HOME explicitly using dynamic resolution (Supports AMD64 & ARM64)
JAVA_BIN=$(which java)
if [ -z "$JAVA_BIN" ]; then
    log_error "Java binary not found in PATH! Docker image might be corrupt."
    exit 1
fi
# Resolve full path (e.g., /usr/lib/jvm/java-21-openjdk-amd64/bin/java)
REAL_JAVA_BIN=$(readlink -f "$JAVA_BIN")
export JAVA_HOME=$(dirname $(dirname "$REAL_JAVA_BIN"))
export PATH="$JAVA_HOME/bin:$PATH"

log_info "Resolved JAVA_HOME to: $JAVA_HOME"
# Verify Java version
java -version 2>&1 | head -n 1 | grep -q "version" && log_info "Java check: OK" || log_error "Java check: FAILED"

log_info "Starting APPredator Action..."

# 1. Configure Settings
# ===================
# Injects CI environment variables into the internal YAML configuration.
if ! python3 /app/scripts/ci/configurator.py; then
   log_error "Configuration failed. Please check your inputs and API keys."
   exit 1
fi

# 2. Prepare Execution Environment
# ==============================
cd /app || { log_error "Failed to change directory to /app"; exit 1; }

# 3. Path Resolution
# =================
# Resolve the APK path relative to the GitHub Workspace mounting point.
WORKSPACE=${GITHUB_WORKSPACE:-/github/workspace}

# Handle GitHub Actions Input inconsistencies (Dash vs Underscore)
RAW_APK_PATH="${INPUT_APK_PATH}"
if [ -z "$RAW_APK_PATH" ]; then
    # Try reading the hyphenated version which bash vars don't like
    RAW_APK_PATH=$(printenv "INPUT_APK-PATH")
fi

if [ -z "$RAW_APK_PATH" ]; then
    log_error "Input 'apk-path' is required but was not provided."
    exit 1
fi

# Determine absolute path
if [[ "$RAW_APK_PATH" != /* ]]; then
    FULL_APK_PATH="$WORKSPACE/$RAW_APK_PATH"
else
    FULL_APK_PATH="$RAW_APK_PATH"
fi

log_info "Target APK: $FULL_APK_PATH"

if [ ! -f "$FULL_APK_PATH" ]; then
    log_error "APK file not found at: $FULL_APK_PATH"
    
    log_info "---------------- DEBUG INFO ----------------"
    log_info "Current User: $(whoami) (UID: $(id -u))"
    log_info "Workspace Mount ($WORKSPACE) permissions:"
    ls -ld "$WORKSPACE" || true
    
    log_info "Searching for any .apk files in workspace (maxdepth 6)..."
    FOUND_APKS=$(find "$WORKSPACE" -maxdepth 6 -name "*.apk" || true)
    
    if [ -z "$FOUND_APKS" ]; then
        log_error "No APK files found anywhere in the workspace! configure your 'Build' step correctly?"
    else
        log_info "Found the following APK candidates:"
        echo "$FOUND_APKS"
        log_info "Please update your 'apk-path' input to match one of the above."
    fi
    log_info "--------------------------------------------"
    exit 1
fi

# 4. Execute Scan
# =================
OUTPUT_FILE="$WORKSPACE/apppredator-report.json"


log_info "Running APPredator scan..."

# Note: We capture the exit status. Currently the CLI returns 0 even on findings,
# but we prepare this logic for future strict modes.
if python3 -m apppredator.cli --output "$OUTPUT_FILE" scan "$FULL_APK_PATH"; then
    log_info "Scan completed successfully."
else
    log_error "Scan failed to complete due to an internal error."
    exit 1
fi

log_info "Report saved to: $OUTPUT_FILE"

