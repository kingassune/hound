# Quick Start: GitHub Webhook Listener

Get started with the webhook listener in 5 minutes!

## Prerequisites

- Python 3.10+
- Hound installed and configured
- LLM API keys set up (OPENAI_API_KEY, DEEPSEEK_API_KEY, etc.)

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs Flask and requests along with Hound's dependencies.

## 2. Add a Subscriber

```bash
python scripts/add_subscriber.py \
  https://github.com/your-org/your-repo \
  your-email@example.com \
  --secret your-webhook-secret
```

Replace:
- `your-org/your-repo` with your GitHub repository
- `your-email@example.com` with your email
- `your-webhook-secret` with a random string (e.g., `openssl rand -hex 20`)

## 3. Configure Email (Optional)

Edit `webhook_config.json` if you want to send actual emails:

```json
{
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "use_tls": true,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "your-email@gmail.com"
  }
}
```

For Gmail, create an [App Password](https://support.google.com/accounts/answer/185833).

## 4. Start the Server

```bash
python server.py
```

Server runs on `http://localhost:5000` by default.

## 5. Test Locally

In another terminal:

```bash
# Send a test webhook
python scripts/test_webhook.py \
  --repo-url https://github.com/your-org/your-repo \
  --secret your-webhook-secret

# Check health
curl http://localhost:5000/health

# View logs
tail -f webhook_server.log
```

## 6. Configure GitHub Webhook

For production, expose your server to the internet:

### Option A: Using ngrok (for testing)

```bash
# Install ngrok: https://ngrok.com/download
ngrok http 5000

# Use the ngrok URL in GitHub webhook settings
```

### Option B: Deploy to a server

Deploy to a VPS, cloud instance, or PaaS (Heroku, Railway, etc.)

### GitHub Configuration

1. Go to your repository **Settings** → **Webhooks** → **Add webhook**
2. **Payload URL**: `http://your-server:5000/webhook` (or ngrok URL)
3. **Content type**: `application/json`
4. **Secret**: Your webhook secret from step 2
5. **Events**: Select "Just the push event"
6. **Active**: ✓ Checked
7. Click **Add webhook**

## 7. Push Code and Verify

```bash
# In your repository
git commit -am "Test webhook"
git push

# Check GitHub webhook delivery
# Settings → Webhooks → Recent Deliveries (should show green checkmark)

# Check server logs
tail -f webhook_server.log
```

You should see:
1. Webhook received
2. Repository cloned
3. Hound scan started
4. Report generated
5. Email sent (if configured)

## Troubleshooting

### Webhook not received?
- Check server is running and accessible
- Verify webhook URL in GitHub settings
- Review GitHub webhook delivery logs

### Signature verification failed?
- Ensure webhook secret matches in both GitHub and `subscribers.json`
- Check that X-Hub-Signature-256 header is present

### Scan failed?
- Verify repository is accessible (public or credentials configured)
- Check Hound is properly configured with LLM API keys
- Review logs in `webhook_scans/org/repo/timestamp/`

### Email not sent?
- Verify SMTP configuration in `webhook_config.json`
- Test SMTP credentials independently
- Check email-related errors in `webhook_server.log`

## Next Steps

- Read [README_WEBHOOK.md](README_WEBHOOK.md) for detailed documentation
- Review [examples/subscribers_example.json](examples/subscribers_example.json) for subscriber format
- Run `bash scripts/integration_test_webhook.sh` for automated testing

## Production Considerations

For production deployment:

1. **Use HTTPS**: Configure reverse proxy (nginx, Apache) with SSL
2. **Authentication**: Add API key/token auth for admin endpoints
3. **Process Manager**: Use systemd, supervisor, or PM2 to keep server running
4. **Monitoring**: Set up logging, metrics, and alerting
5. **Scaling**: Use Redis for job queue and multiple worker processes
6. **Security**: Firewall rules, rate limiting, input validation

Example systemd service file:

```ini
[Unit]
Description=Hound Webhook Server
After=network.target

[Service]
Type=simple
User=hound
WorkingDirectory=/opt/hound
ExecStart=/usr/bin/python3 server.py --port 5000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Support

- Full documentation: [README_WEBHOOK.md](README_WEBHOOK.md)
- Integration tests: `bash scripts/integration_test_webhook.sh`
- Unit tests: `python -m pytest tests/test_webhook_server.py`
- Issues: https://github.com/kingassune/hound/issues
