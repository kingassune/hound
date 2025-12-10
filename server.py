#!/usr/bin/env python3
"""
GitHub Webhook Listener for Monthly Subscribers

This server listens for GitHub push events from subscribed customers and triggers
Hound security scans on the updated branches. The resulting HTML reports are
emailed to the registered user.

Usage:
    python server.py [--port 5000] [--host 0.0.0.0]
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import shutil
import smtplib
import subprocess
import sys
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from queue import Queue
from typing import Dict, Optional

from flask import Flask, request, jsonify

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webhook_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
CONFIG_FILE = Path("webhook_config.json")
SUBSCRIBERS_DB = Path("subscribers.json")
WORK_QUEUE = Queue()


class SubscriberDatabase:
    """Simple JSON-based subscriber database."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """Create empty database if it doesn't exist."""
        if not self.db_path.exists():
            default_db = {
                "subscribers": {}
            }
            self.db_path.write_text(json.dumps(default_db, indent=2))
            logger.info(f"Created subscriber database at {self.db_path}")
    
    def get_subscriber(self, repo_url: str) -> Optional[Dict]:
        """
        Check if a repository is from a paying subscriber.
        
        Args:
            repo_url: Repository URL (e.g., https://github.com/owner/repo)
        
        Returns:
            Subscriber info dict if found, None otherwise
        """
        try:
            data = json.loads(self.db_path.read_text())
            subscribers = data.get("subscribers", {})
            
            # Normalize repo URL (remove .git suffix, trailing slash, etc.)
            normalized_url = repo_url.rstrip('/').replace('.git', '')
            
            # Try exact match
            if normalized_url in subscribers:
                return subscribers[normalized_url]
            
            # Try matching by owner/repo pattern
            for sub_url, sub_data in subscribers.items():
                if sub_url.rstrip('/').replace('.git', '') == normalized_url:
                    return sub_data
            
            return None
        except Exception as e:
            logger.error(f"Error reading subscriber database: {e}")
            return None
    
    def add_subscriber(self, repo_url: str, email: str, webhook_secret: Optional[str] = None):
        """Add a new subscriber to the database."""
        try:
            data = json.loads(self.db_path.read_text())
            normalized_url = repo_url.rstrip('/').replace('.git', '')
            
            data["subscribers"][normalized_url] = {
                "email": email,
                "webhook_secret": webhook_secret,
                "added_at": datetime.now(timezone.utc).isoformat(),
                "scan_count": 0
            }
            
            self.db_path.write_text(json.dumps(data, indent=2))
            logger.info(f"Added subscriber: {normalized_url}")
            return True
        except Exception as e:
            logger.error(f"Error adding subscriber: {e}")
            return False


class WebhookConfig:
    """Configuration manager for webhook server."""
    
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self._ensure_config_exists()
        self.config = self._load_config()
    
    def _ensure_config_exists(self):
        """Create default configuration if it doesn't exist."""
        if not self.config_path.exists():
            default_config = {
                "smtp": {
                    "host": "localhost",
                    "port": 587,
                    "use_tls": True,
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
                    "verify_signature": True
                },
                "output": {
                    "base_dir": "./webhook_scans"
                }
            }
            self.config_path.write_text(json.dumps(default_config, indent=2))
            logger.info(f"Created default configuration at {self.config_path}")
    
    def _load_config(self) -> Dict:
        """Load configuration from file."""
        try:
            return json.loads(self.config_path.read_text())
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def get(self, *keys, default=None):
        """Get nested configuration value."""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
        return value if value is not None else default


def verify_webhook_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """
    Verify GitHub webhook signature.
    
    Args:
        payload_body: Raw request body
        signature_header: X-Hub-Signature-256 header value
        secret: Webhook secret
    
    Returns:
        True if signature is valid, False otherwise
    """
    if not signature_header:
        return False
    
    try:
        hash_algorithm, github_signature = signature_header.split('=')
    except ValueError:
        return False
    
    if hash_algorithm != 'sha256':
        return False
    
    # Calculate expected signature
    mac = hmac.new(secret.encode(), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    
    # Compare signatures using constant-time comparison
    return hmac.compare_digest(expected_signature, github_signature)


def send_email(to_email: str, subject: str, html_content: str, config: WebhookConfig):
    """
    Send email with HTML report.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        html_content: HTML content to send
        config: WebhookConfig instance
    """
    try:
        smtp_host = config.get('smtp', 'host', default='localhost')
        smtp_port = config.get('smtp', 'port', default=587)
        use_tls = config.get('smtp', 'use_tls', default=True)
        username = config.get('smtp', 'username', default='')
        password = config.get('smtp', 'password', default='')
        from_email = config.get('smtp', 'from_email', default='security@hound.dev')
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        
        # Attach HTML content
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


def run_hound_scan(repo_url: str, branch: str, subscriber: Dict, config: WebhookConfig) -> Optional[Path]:
    """
    Run Hound scan on the repository.
    
    Args:
        repo_url: Repository URL
        branch: Branch name
        subscriber: Subscriber information
        config: WebhookConfig instance
    
    Returns:
        Path to generated HTML report if successful, None otherwise
    """
    try:
        # Create output directory
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
        org_name = repo_url.rstrip('/').split('/')[-2] if '/' in repo_url else 'unknown'
        
        base_dir = Path(config.get('output', 'base_dir', default='./webhook_scans'))
        output_dir = base_dir / org_name / repo_name / timestamp
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Clone repository to temp location
        temp_dir = output_dir / "repo"
        logger.info(f"Cloning {repo_url} (branch: {branch})")
        
        clone_cmd = [
            'git', 'clone',
            '--depth', '1',
            '--branch', branch,
            repo_url,
            str(temp_dir)
        ]
        
        result = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes
        )
        
        if result.returncode != 0:
            logger.error(f"Failed to clone repository: {result.stderr}")
            return None
        
        # Generate unique project name
        project_name = f"webhook_{org_name}_{repo_name}_{timestamp}"
        
        # Get hound script path
        hound_script = config.get('hound', 'script_path', default='./hound.py')
        if not Path(hound_script).exists():
            logger.error(f"Hound script not found at {hound_script}")
            return None
        
        # Create Hound project
        logger.info(f"Creating Hound project: {project_name}")
        create_cmd = [
            sys.executable,
            hound_script,
            'project', 'create',
            project_name,
            str(temp_dir)
        ]
        
        result = subprocess.run(
            create_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            logger.error(f"Failed to create project: {result.stderr}")
            return None
        
        # Run audit with headless mode
        logger.info(f"Running Hound audit on {project_name}")
        audit_cmd = [
            sys.executable,
            hound_script,
            'agent', 'audit',
            project_name,
            '--headless'
        ]
        
        timeout = config.get('hound', 'default_timeout', default=3600)
        result = subprocess.run(
            audit_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.warning(f"Audit completed with warnings: {result.stderr}")
        
        # Generate HTML report
        logger.info(f"Generating report for {project_name}")
        report_path = output_dir / "audit_report.html"
        report_cmd = [
            sys.executable,
            hound_script,
            'report',
            project_name,
            '--output', str(report_path),
            '--format', 'html'
        ]
        
        result = subprocess.run(
            report_cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            logger.error(f"Failed to generate report: {result.stderr}")
            return None
        
        # Cleanup cloned repo
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        
        logger.info(f"Scan completed successfully. Report: {report_path}")
        return report_path
        
    except subprocess.TimeoutExpired:
        logger.error(f"Scan timed out for {repo_url}")
        return None
    except Exception as e:
        logger.error(f"Error running scan: {e}")
        return None


def process_webhook_job(job: Dict, subscriber_db: SubscriberDatabase, config: WebhookConfig):
    """
    Process a webhook job from the queue.
    
    Args:
        job: Job dictionary with repo_url, branch, and subscriber info
        subscriber_db: SubscriberDatabase instance
        config: WebhookConfig instance
    """
    try:
        repo_url = job['repo_url']
        branch = job['branch']
        subscriber = job['subscriber']
        
        logger.info(f"Processing scan job for {repo_url} (branch: {branch})")
        
        # Run the scan
        report_path = run_hound_scan(repo_url, branch, subscriber, config)
        
        if report_path and report_path.exists():
            # Read the HTML report
            html_content = report_path.read_text()
            
            # Send email with report
            subject = f"Hound Security Scan Report - {repo_url.split('/')[-1]}"
            send_email(
                to_email=subscriber['email'],
                subject=subject,
                html_content=html_content,
                config=config
            )
            
            logger.info(f"Job completed successfully for {repo_url}")
        else:
            logger.error(f"Scan failed for {repo_url}, no report generated")
            
    except Exception as e:
        logger.error(f"Error processing job: {e}")


def worker_thread(subscriber_db: SubscriberDatabase, config: WebhookConfig):
    """Background worker thread to process scan jobs."""
    logger.info("Worker thread started")
    while True:
        job = WORK_QUEUE.get()
        if job is None:  # Shutdown signal
            break
        try:
            process_webhook_job(job, subscriber_db, config)
        except Exception as e:
            logger.error(f"Worker thread error: {e}")
        finally:
            WORK_QUEUE.task_done()
    logger.info("Worker thread stopped")


@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle GitHub webhook POST requests."""
    try:
        # Get configuration
        config = WebhookConfig(CONFIG_FILE)
        subscriber_db = SubscriberDatabase(SUBSCRIBERS_DB)
        
        # Parse payload
        payload = request.json
        if not payload:
            logger.warning("Received webhook with no payload")
            return jsonify({"error": "No payload"}), 400
        
        # Extract repository info
        repository = payload.get('repository', {})
        repo_url = repository.get('html_url') or repository.get('clone_url', '')
        
        if not repo_url:
            logger.warning("Webhook missing repository URL")
            return jsonify({"error": "Missing repository URL"}), 400
        
        # Check if repository is from a paying subscriber
        subscriber = subscriber_db.get_subscriber(repo_url)
        if not subscriber:
            logger.info(f"Webhook from non-subscriber: {repo_url}")
            return jsonify({"status": "ignored", "reason": "not a subscriber"}), 200
        
        # Verify webhook signature if configured
        if config.get('server', 'verify_signature', default=True):
            webhook_secret = subscriber.get('webhook_secret')
            if webhook_secret:
                signature = request.headers.get('X-Hub-Signature-256', '')
                if not verify_webhook_signature(request.data, signature, webhook_secret):
                    logger.warning(f"Invalid webhook signature for {repo_url}")
                    return jsonify({"error": "Invalid signature"}), 401
        
        # Only process push events
        event_type = request.headers.get('X-GitHub-Event', '')
        if event_type != 'push':
            logger.info(f"Ignoring non-push event: {event_type}")
            return jsonify({"status": "ignored", "reason": "not a push event"}), 200
        
        # Extract branch info
        ref = payload.get('ref', '')
        branch = ref.split('/')[-1] if '/' in ref else ref
        if not branch:
            branch = repository.get('default_branch', 'main')
        
        logger.info(f"Received push webhook for {repo_url} (branch: {branch})")
        
        # Queue the scan job
        job = {
            'repo_url': repo_url,
            'branch': branch,
            'subscriber': subscriber,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        WORK_QUEUE.put(job)
        
        return jsonify({
            "status": "queued",
            "repository": repo_url,
            "branch": branch
        }), 202
        
    except Exception as e:
        logger.error(f"Error handling webhook: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "queue_size": WORK_QUEUE.qsize(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


@app.route('/subscribers', methods=['GET'])
def list_subscribers():
    """List all subscribers (for admin use)."""
    try:
        subscriber_db = SubscriberDatabase(SUBSCRIBERS_DB)
        data = json.loads(subscriber_db.db_path.read_text())
        subscribers = data.get("subscribers", {})
        
        # Remove sensitive info
        public_info = {}
        for url, info in subscribers.items():
            public_info[url] = {
                "email": info.get("email", ""),
                "added_at": info.get("added_at", ""),
                "scan_count": info.get("scan_count", 0)
            }
        
        return jsonify({"subscribers": public_info}), 200
    except Exception as e:
        logger.error(f"Error listing subscribers: {e}")
        return jsonify({"error": "Internal server error"}), 500


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="GitHub Webhook Listener for Monthly Subscribers"
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Server port (default: 5000)'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Server host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=2,
        help='Number of worker threads (default: 2)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = WebhookConfig(CONFIG_FILE)
    subscriber_db = SubscriberDatabase(SUBSCRIBERS_DB)
    
    # Start worker threads
    workers = []
    for i in range(args.workers):
        worker = threading.Thread(
            target=worker_thread,
            args=(subscriber_db, config),
            daemon=True
        )
        worker.start()
        workers.append(worker)
        logger.info(f"Started worker thread {i+1}/{args.workers}")
    
    # Start Flask server
    logger.info(f"Starting webhook server on {args.host}:{args.port}")
    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        # Shutdown workers
        for _ in workers:
            WORK_QUEUE.put(None)
        for worker in workers:
            worker.join(timeout=5)


if __name__ == '__main__':
    main()
