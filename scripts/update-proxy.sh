#!/bin/bash
# Auto-update script for DGFT Proxy Server on Linode
# This script pulls latest changes from git and restarts the proxy

set -e

PROXY_DIR="/opt/dgft-proxy"
LOG_FILE="/opt/dgft-proxy/update.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "🚀 Starting proxy update..."

# Change to proxy directory
cd "$PROXY_DIR" || {
    log "❌ Error: Cannot cd to $PROXY_DIR"
    exit 1
}

# Check if git repo exists
if [ ! -d ".git" ]; then
    log "❌ Error: Not a git repository. Run setup-git-deployment.sh first."
    exit 1
fi

# Get current commit hash
OLD_COMMIT=$(git rev-parse HEAD)
log "📌 Current commit: $OLD_COMMIT"

# Pull latest changes
log "📥 Pulling latest changes from git..."
if git pull origin main 2>&1 | tee -a "$LOG_FILE"; then
    NEW_COMMIT=$(git rev-parse HEAD)
    
    if [ "$OLD_COMMIT" = "$NEW_COMMIT" ]; then
        log "✅ Already up to date (no changes)"
    else
        log "✅ Updated from $OLD_COMMIT to $NEW_COMMIT"
        
        # Restart PM2 process
        log "🔄 Restarting proxy server..."
        if pm2 restart dgft-proxy 2>&1 | tee -a "$LOG_FILE"; then
            log "✅ Proxy restarted successfully"
            
            # Wait a moment for startup
            sleep 2
            
            # Verify proxy is running
            if pm2 list | grep -q "dgft-proxy.*online"; then
                log "✅ Proxy is running and healthy"
            else
                log "⚠️  Warning: Proxy may not be running. Check: pm2 logs dgft-proxy"
            fi
        else
            log "❌ Error: Failed to restart proxy"
            exit 1
        fi
    fi
else
    log "❌ Error: Failed to pull from git"
    exit 1
fi

log "✅ Update complete!"

