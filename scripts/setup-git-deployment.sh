#!/bin/bash
# Setup Git-based deployment for DGFT Proxy Server on Linode
# Run this ONCE on your Linode VM to initialize git repository

set -e

PROXY_DIR="/opt/dgft-proxy"
GIT_REPO_URL="${1:-}"  # Pass GitHub/GitLab repo URL as first argument

echo "🚀 Setting up Git-based deployment for DGFT Proxy..."

# Check if proxy directory exists
if [ ! -d "$PROXY_DIR" ]; then
    echo "❌ Error: Proxy directory $PROXY_DIR does not exist."
    echo "   Run setup-proxy.sh first to create the proxy server."
    exit 1
fi

cd "$PROXY_DIR" || exit 1

# Check if already a git repo
if [ -d ".git" ]; then
    echo "⚠️  Warning: Already a git repository."
    read -p "   Do you want to reinitialize? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   Skipping git initialization."
        exit 0
    fi
    rm -rf .git
fi

# Initialize git repository
echo "📦 Initializing git repository..."
git init

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Logs
*.log
update.log

# Node modules (if any)
node_modules/

# PM2
.pm2/

# Environment files
.env
.env.local

# OS files
.DS_Store
Thumbs.db
EOF

# Add all files
echo "📤 Adding files to git..."
git add .

# Initial commit
echo "💾 Creating initial commit..."
git commit -m "Initial proxy server setup"

# Add remote if URL provided
if [ -n "$GIT_REPO_URL" ]; then
    echo "🔗 Adding remote repository: $GIT_REPO_URL"
    git remote add origin "$GIT_REPO_URL"
    
    # Check if remote branch exists
    if git ls-remote --heads origin main &>/dev/null; then
        echo "📥 Remote 'main' branch exists. Pulling..."
        git pull origin main --allow-unrelated-histories || true
    else
        echo "📤 Pushing to remote..."
        git branch -M main
        git push -u origin main || {
            echo "⚠️  Warning: Could not push to remote. You may need to:"
            echo "   1. Create the repository on GitHub/GitLab first"
            echo "   2. Set up SSH keys or use HTTPS with credentials"
            echo "   3. Run: git push -u origin main"
        }
    fi
else
    echo ""
    echo "⚠️  No remote repository URL provided."
    echo "   To add remote later, run:"
    echo "   cd $PROXY_DIR"
    echo "   git remote add origin <your-repo-url>"
    echo "   git branch -M main"
    echo "   git push -u origin main"
fi

# Make update script executable
if [ -f "scripts/update-proxy.sh" ]; then
    chmod +x scripts/update-proxy.sh
    echo "✅ Made update-proxy.sh executable"
elif [ -f "update-proxy.sh" ]; then
    chmod +x update-proxy.sh
    echo "✅ Made update-proxy.sh executable"
fi

echo ""
echo "✅ Git deployment setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. If you haven't added a remote, add your GitHub/GitLab repo:"
echo "   cd $PROXY_DIR"
echo "   git remote add origin <your-repo-url>"
echo "   git push -u origin main"
echo ""
echo "2. To update the proxy manually, run:"
echo "   cd $PROXY_DIR"
echo "   ./scripts/update-proxy.sh"
echo ""
echo "3. Or set up GitHub Actions for automatic deployment (see .github/workflows/deploy-proxy.yml)"

