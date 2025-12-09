# GitHub Webhook Listener for Monthly Subscribers

This document describes the webhook server that enables automated Hound security scans for monthly subscribers when they push code to their repositories.

## Overview

The webhook server listens for GitHub push events from subscribed repositories and automatically:

1. Receives GitHub webhook POST requests
2. Verifies the repository is from a paying subscriber
3. Validates webhook signatures for security
4. Queues a background job to run a Hound security scan
5. Emails the resulting HTML report to the registered user

## Architecture

```
GitHub Push → Webhook Server → Job Queue → Hound Scan → Email Report
```

**Components:**

- **server.py**: Flask-based webhook server with background job processing
- **subscribers.json**: JSON database of paying subscribers
- **webhook_config.json**: Server and email configuration
- **scripts/add_subscriber.py**: Helper to add new subscribers
- **scripts/test_webhook.py**: Testing tool with mock payloads

## Installation

### Prerequisites

- Python 3.10+
- Hound installed and configured
- Git available in PATH
- SMTP server for sending emails (or use localhost for testing)

### Install Dependencies

```bash
pip install -r requirements.txt
```

This installs Flask and requests in addition to Hound's existing dependencies.

## Configuration

### 1. Server Configuration

On first run, the server creates `webhook_config.json` with default settings:

```json
{
  "smtp": {
    "host": "localhost",
    "port": 587,
    "use_tls": true,
    "username": "",
    "password": "",
    "from_email": "security@hound.dev"
  },
  "hound": {
    "script_path": "./hound.py",
    "default_timeout": 3600
  },
  "server": {
    "port": 5000,
    "host": "0.0.0.0",
    "verify_signature": true
  },
  "output": {
    "base_dir": "./webhook_scans"
  }
}
```

**Configuration Options:**

- **smtp**: Email server settings for sending reports
  - `host`: SMTP server hostname
  - `port`: SMTP server port (usually 587 for TLS)
  - `use_tls`: Enable TLS encryption
  - `username`: SMTP authentication username
  - `password`: SMTP authentication password
  - `from_email`: Sender email address

- **hound**: Hound execution settings
  - `script_path`: Path to hound.py (default: ./hound.py)
  - `default_timeout`: Maximum scan time in seconds (default: 3600)

- **server**: Webhook server settings
  - `port`: Server port (default: 5000)
  - `host`: Server host (default: 0.0.0.0)
  - `verify_signature`: Enable webhook signature verification (default: true)

- **output**: Scan output settings
  - `base_dir`: Base directory for scan results (default: ./webhook_scans)

### 2. Add Subscribers

Use the helper script to add paying subscribers:

```bash
# Add a subscriber with webhook secret
python scripts/add_subscriber.py https://github.com/owner/repo user@example.com --secret mysecret123

# Add a subscriber without webhook secret (signature verification disabled)
python scripts/add_subscriber.py https://github.com/owner/repo user@example.com
```

This creates/updates `subscribers.json`:

```json
{
  "subscribers": {
    "https://github.com/owner/repo": {
      "email": "user@example.com",
      "webhook_secret": "mysecret123",
      "added_at": "2024-12-09T22:30:00.000000+00:00",
      "scan_count": 0
    }
  }
}
```

### 3. Configure GitHub Webhook

In your GitHub repository:

1. Go to **Settings** → **Webhooks** → **Add webhook**
2. Set **Payload URL** to `http://your-server:5000/webhook`
3. Set **Content type** to `application/json`
4. Set **Secret** to match the webhook_secret in subscribers.json
5. Select **Just the push event**
6. Ensure **Active** is checked
7. Click **Add webhook**

**For Testing Locally:**

Use a service like [ngrok](https://ngrok.com/) to expose your local server:

```bash
ngrok http 5000
# Use the ngrok URL in GitHub webhook settings
```

## Usage

### Start the Server

```bash
python server.py
```

**Options:**

```bash
python server.py --port 5000 --host 0.0.0.0 --workers 2
```

- `--port`: Server port (default: 5000)
- `--host`: Server host (default: 0.0.0.0)
- `--workers`: Number of background worker threads (default: 2)

The server will:
- Start Flask on the specified host/port
- Launch background worker threads to process scan jobs
- Log activity to `webhook_server.log` and console

### Test with Mock Payload

Before configuring GitHub webhooks, test locally:

```bash
# 1. Add a test subscriber
python scripts/add_subscriber.py https://github.com/testowner/testrepo test@example.com

# 2. Start the server
python server.py

# 3. In another terminal, send a test webhook
python scripts/test_webhook.py --repo-url https://github.com/testowner/testrepo
```

**Expected Output:**

```
Sending webhook to http://localhost:5000/webhook
Repository: https://github.com/testowner/testrepo
Branch: refs/heads/main

Response Status: 202
Response Body: {"status":"queued","repository":"https://github.com/testowner/testrepo","branch":"main"}

✓ Webhook accepted! Scan has been queued.
```

Check the logs to see the scan progress:

```bash
tail -f webhook_server.log
```

## API Endpoints

### POST /webhook

Receives GitHub push webhooks.

**Headers:**
- `Content-Type: application/json`
- `X-GitHub-Event: push`
- `X-Hub-Signature-256: sha256=...` (if signature verification enabled)

**Request Body:** GitHub push event payload

**Response:**
- `202`: Scan queued successfully
- `200`: Webhook received but ignored (non-subscriber or non-push event)
- `400`: Invalid payload
- `401`: Invalid signature
- `500`: Internal server error

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "queue_size": 0,
  "timestamp": "2024-12-09T22:30:00.000000+00:00"
}
```

### GET /subscribers

List all subscribers (admin endpoint).

**Response:**
```json
{
  "subscribers": {
    "https://github.com/owner/repo": {
      "email": "user@example.com",
      "added_at": "2024-12-09T22:30:00.000000+00:00",
      "scan_count": 5
    }
  }
}
```

## Workflow

When a GitHub push event is received:

1. **Webhook Validation**
   - Verify payload structure
   - Extract repository URL
   - Check if repository is from a paying subscriber
   - Validate webhook signature (if configured)

2. **Job Queuing**
   - Add scan job to background queue
   - Return 202 Accepted immediately

3. **Background Scanning** (by worker thread)
   - Clone repository to temporary location
   - Create Hound project
   - Run `hound.py agent audit --headless`
   - Generate HTML report with `hound.py report`
   - Clean up temporary files

4. **Email Delivery**
   - Read generated HTML report
   - Send via SMTP to subscriber's registered email
   - Log completion

## Output Structure

Scan results are organized by organization, repository, and timestamp:

```
webhook_scans/
├── owner/
│   └── repo/
│       ├── 20241209_143000/
│       │   └── audit_report.html
│       └── 20241209_150000/
│           └── audit_report.html
└── another-org/
    └── another-repo/
        └── 20241209_160000/
            └── audit_report.html
```

## Security Considerations

### Webhook Signature Verification

The server supports GitHub webhook signature verification using HMAC-SHA256:

1. Configure webhook secret in GitHub
2. Add the same secret to subscribers.json for each repository
3. The server automatically verifies signatures before processing

**Disable signature verification** (not recommended for production):

Edit `webhook_config.json`:
```json
{
  "server": {
    "verify_signature": false
  }
}
```

### Network Security

- Use HTTPS in production (configure reverse proxy like nginx)
- Restrict access to admin endpoints (/subscribers)
- Consider firewall rules to allow only GitHub's webhook IPs
- Use environment variables for sensitive credentials instead of config files

### Email Security

- Use authenticated SMTP with TLS
- Consider using application-specific passwords
- Validate email addresses before adding subscribers

## Troubleshooting

### Webhook not received

1. Check GitHub webhook delivery status (Settings → Webhooks → Recent Deliveries)
2. Verify server is running and accessible
3. Check firewall rules
4. Review `webhook_server.log` for errors

### Signature verification fails

1. Ensure webhook secret matches in GitHub and subscribers.json
2. Check that X-Hub-Signature-256 header is present
3. Verify payload is being sent as application/json

### Scan fails or times out

1. Check that repository is accessible (public or has credentials configured)
2. Verify Hound is properly configured with LLM API keys
3. Increase timeout in webhook_config.json
4. Review scan logs in webhook_scans/org/repo/timestamp/

### Email not sent

1. Verify SMTP configuration in webhook_config.json
2. Check SMTP server is accessible
3. Test SMTP credentials independently
4. Review email-related errors in webhook_server.log

### Worker thread errors

1. Increase number of workers if jobs are backing up
2. Check system resources (CPU, memory, disk space)
3. Review worker thread logs for specific errors

## Limitations

- Sequential processing per worker (configure multiple workers for concurrency)
- Requires public repositories or configured Git credentials
- Email sent as HTML only (no attachments)
- No built-in authentication for admin endpoints
- Job queue is in-memory (lost on restart)

## Future Enhancements

Potential improvements:

- Persistent job queue (Redis, database)
- Authentication for admin endpoints
- Web dashboard for monitoring
- Support for private repositories with credential management
- Configurable scan parameters per repository
- Multiple notification channels (Slack, Discord, etc.)
- Retry logic for failed scans
- Rate limiting per subscriber
- Metrics and analytics dashboard

## Example: Complete Setup

### 1. Install and Configure

```bash
# Install dependencies
pip install -r requirements.txt

# Configure SMTP (edit webhook_config.json)
cat > webhook_config.json <<EOF
{
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "use_tls": true,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "your-email@gmail.com"
  },
  "hound": {
    "script_path": "./hound.py",
    "default_timeout": 3600
  },
  "server": {
    "port": 5000,
    "host": "0.0.0.0",
    "verify_signature": true
  },
  "output": {
    "base_dir": "./webhook_scans"
  }
}
EOF
```

### 2. Add a Subscriber

```bash
python scripts/add_subscriber.py \
  https://github.com/myorg/myrepo \
  customer@example.com \
  --secret my-webhook-secret-123
```

### 3. Configure GitHub Webhook

1. Go to https://github.com/myorg/myrepo/settings/hooks
2. Click "Add webhook"
3. Payload URL: `https://your-server.com/webhook` (or ngrok URL for testing)
4. Content type: `application/json`
5. Secret: `my-webhook-secret-123`
6. Events: Just the push event
7. Active: ✓

### 4. Start the Server

```bash
python server.py --workers 2
```

### 5. Push Code

```bash
cd myrepo
git commit -am "Test commit"
git push origin main
```

### 6. Verify

- Check webhook delivery in GitHub (green checkmark)
- Monitor logs: `tail -f webhook_server.log`
- Wait for email with HTML report
- Review scan results in `webhook_scans/myorg/myrepo/`

## Support

For issues or questions:

1. Check this documentation
2. Review `webhook_server.log` for detailed execution logs
3. Test with `scripts/test_webhook.py` to isolate issues
4. Verify Hound works independently: `python hound.py --help`
5. Open an issue on the Hound GitHub repository

## Files Reference

### Core Files
- **server.py**: Main webhook server application
- **subscribers.json**: Subscriber database (created on first run)
- **webhook_config.json**: Configuration file (created on first run)
- **webhook_server.log**: Server activity log

### Helper Scripts
- **scripts/add_subscriber.py**: Add subscribers to database
- **scripts/test_webhook.py**: Test webhook with mock payloads

### Documentation
- **README_WEBHOOK.md**: This file

## Summary

The webhook listener provides a production-ready solution for automating Hound security scans for monthly subscribers. It integrates seamlessly with GitHub webhooks, processes scans in the background, and delivers HTML reports via email.
