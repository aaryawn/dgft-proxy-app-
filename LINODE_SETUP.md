# 🚀 ONE-COMMAND LINODE PROXY SETUP

## IP Address to Whitelist in DGFT Portal
**194.195.119.120**

## ⚡ SUPER SIMPLE - Just Copy & Paste This:

**Step 1:** Open Linode's web console (click "Launch LISH Console" in Linode dashboard)

**Step 2:** Copy and paste this ENTIRE command:

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/setup-proxy.sh | bash
```

**OR** if that doesn't work, copy the entire `setup-proxy.sh` file contents and paste it into the console.

**That's it!** The script does everything automatically.

## Step 5: Test Proxy

From your local machine:

```bash
curl http://194.195.119.120:3000/genebrc/getAccessToken
```

Should return an error (expected - needs auth), but confirms proxy is running.

## Step 6: Add IP to DGFT Portal

1. Go to DGFT Portal → API Consumer Settings
2. Add IP: **194.195.119.120**
3. Save (Sandbox takes ~10 min, Production takes up to 24h)

## Step 7: Update Vercel Environment Variable

Add to Vercel project settings → Environment Variables:

```
DGFT_PROXY_URL=http://194.195.119.120:3000
```

Then redeploy Vercel.

## Step 8: Set Up Automated Deployment (Optional but Recommended)

After initial setup, configure automatic deployment so you never need to manually update the proxy again:

See `PROXY_AUTOMATED_DEPLOYMENT.md` for full instructions.

**Quick setup:**
1. Run `scripts/setup-git-deployment.sh` on Linode
2. Add GitHub Actions secrets (LINODE_HOST, LINODE_USER, LINODE_SSH_KEY)
3. Push changes - they deploy automatically!

## Troubleshooting

Check proxy logs:
```bash
pm2 logs dgft-proxy
```

Restart proxy:
```bash
pm2 restart dgft-proxy
```

**For automated deployment issues**, see `PROXY_AUTOMATED_DEPLOYMENT.md`

