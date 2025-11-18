# Automated Proxy Deployment Guide

## Overview

This guide sets up **automatic deployment** for the Linode proxy server. Once configured, updates happen automatically when you push changes to GitHub - no manual SSH or console access needed!

## Quick Start (One-Time Setup)

### Step 1: Initial Proxy Setup

If you haven't set up the proxy yet, follow `LINODE_SETUP.md` first.

### Step 2: Set Up Git Repository on Linode

**On your Linode VM** (via SSH or Console):

```bash
# Copy the setup script to Linode
scp scripts/setup-git-deployment.sh root@194.195.119.120:/tmp/

# SSH into Linode
ssh root@194.195.119.120

# Run the setup script
cd /opt/dgft-proxy
bash /tmp/setup-git-deployment.sh <your-github-repo-url>
```

**Or manually via Console:**

1. Open Linode Console
2. Copy and paste `scripts/setup-git-deployment.sh` content
3. Run: `bash setup-git-deployment.sh <your-github-repo-url>`

### Step 3: Push Proxy Files to GitHub

**On your local machine:**

```bash
# Add proxy files to git
git add proxy-server.js scripts/ .github/workflows/

# Commit
git commit -m "Add proxy server and deployment automation"

# Push to GitHub
git push origin main
```

### Step 4: Configure GitHub Actions Secrets

1. Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**
2. Add these secrets:

   - `LINODE_HOST`: `194.195.119.120`
   - `LINODE_USER`: `root` (or your SSH user)
   - `LINODE_SSH_KEY`: Your private SSH key (contents of `~/.ssh/id_rsa` or similar)
   - `LINODE_SSH_PORT`: `22` (optional, defaults to 22)

**To get your SSH key:**

```bash
# If you don't have an SSH key, generate one:
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# Copy the public key to Linode (one-time):
ssh-copy-id root@194.195.119.120

# Copy the private key for GitHub Secrets:
cat ~/.ssh/id_rsa
```

**Important:** Never share your private key publicly. Only add it to GitHub Secrets.

### Step 5: Test Automatic Deployment

1. Make a small change to `proxy-server.js` (add a comment)
2. Commit and push:
   ```bash
   git add proxy-server.js
   git commit -m "Test auto-deployment"
   git push origin main
   ```
3. Check GitHub Actions:
   - Go to your repo → **Actions** tab
   - You should see "Deploy Proxy to Linode" workflow running
   - Wait for it to complete (should take ~30 seconds)

4. Verify on Linode:
   ```bash
   ssh root@194.195.119.120 "cd /opt/dgft-proxy && git log --oneline -1"
   ```
   Should show your latest commit.

## How It Works

1. **You push to GitHub** → Changes to `proxy-server.js` or deployment files
2. **GitHub Actions triggers** → `.github/workflows/deploy-proxy.yml` runs
3. **SSH to Linode** → GitHub Actions connects to your Linode VM
4. **Run update script** → `scripts/update-proxy.sh` pulls latest changes and restarts PM2
5. **Done!** → Proxy is updated automatically

## Manual Update (Fallback)

If automatic deployment fails, you can still update manually:

**Option A: SSH and run update script**
```bash
ssh root@194.195.119.120
cd /opt/dgft-proxy
./scripts/update-proxy.sh
```

**Option B: Direct git pull**
```bash
ssh root@194.195.119.120
cd /opt/dgft-proxy
git pull origin main
pm2 restart dgft-proxy
```

## Troubleshooting

### GitHub Actions Fails with "Permission Denied"

**Problem:** SSH key not set up correctly.

**Solution:**
1. Verify SSH key works: `ssh -i ~/.ssh/id_rsa root@194.195.119.120`
2. Make sure private key is copied correctly to GitHub Secrets (include `-----BEGIN` and `-----END` lines)
3. Check `LINODE_USER` matches your SSH user

### Update Script Not Found

**Problem:** `scripts/update-proxy.sh` doesn't exist on Linode.

**Solution:**
```bash
ssh root@194.195.119.120
cd /opt/dgft-proxy
# Copy the script from your repo
git pull origin main
chmod +x scripts/update-proxy.sh
```

### Proxy Not Restarting

**Problem:** PM2 process not restarting after update.

**Solution:**
```bash
ssh root@194.195.119.120
pm2 list  # Check if dgft-proxy exists
pm2 restart dgft-proxy  # Manual restart
pm2 logs dgft-proxy  # Check logs
```

### Git Pull Fails

**Problem:** Linode can't pull from GitHub (authentication issue).

**Solution:**
1. Set up SSH keys for git:
   ```bash
   ssh root@194.195.119.120
   ssh-keygen -t rsa -b 4096
   cat ~/.ssh/id_rsa.pub  # Add this to GitHub → Settings → SSH Keys
   ```
2. Or use HTTPS with personal access token:
   ```bash
   git remote set-url origin https://<token>@github.com/user/repo.git
   ```

## Benefits

✅ **No manual SSH needed** - Updates happen automatically  
✅ **Version control** - All proxy changes tracked in git  
✅ **Rollback easy** - `git revert` and push to rollback  
✅ **Audit trail** - GitHub Actions logs show all deployments  
✅ **Fast** - Updates deploy in ~30 seconds  

## Next Steps

Once automated deployment is working:

1. **Test it** - Make a small change and verify it deploys
2. **Monitor** - Check GitHub Actions tab for deployment status
3. **Relax** - No more manual proxy updates needed! 🎉

