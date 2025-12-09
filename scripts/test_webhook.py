#!/usr/bin/env python3
"""
Test the webhook server with mock GitHub payloads.

Usage:
    python scripts/test_webhook.py [--url http://localhost:5000] [--repo-url REPO_URL]
    
Example:
    python scripts/test_webhook.py --url http://localhost:5000 --repo-url https://github.com/owner/repo
"""

import argparse
import hashlib
import hmac
import json
import sys

import requests


def create_mock_payload(repo_url: str) -> dict:
    """Create a mock GitHub push payload."""
    # Parse repo URL
    parts = repo_url.rstrip('/').replace('.git', '').split('/')
    owner = parts[-2] if len(parts) >= 2 else 'testowner'
    repo = parts[-1] if len(parts) >= 1 else 'testrepo'
    
    payload = {
        "ref": "refs/heads/main",
        "before": "0000000000000000000000000000000000000000",
        "after": "1111111111111111111111111111111111111111",
        "repository": {
            "id": 12345678,
            "name": repo,
            "full_name": f"{owner}/{repo}",
            "html_url": repo_url,
            "clone_url": f"{repo_url}.git",
            "default_branch": "main",
            "owner": {
                "name": owner,
                "login": owner
            }
        },
        "pusher": {
            "name": "testuser",
            "email": "testuser@example.com"
        },
        "sender": {
            "login": "testuser",
            "id": 987654
        },
        "commits": [
            {
                "id": "1111111111111111111111111111111111111111",
                "message": "Test commit",
                "author": {
                    "name": "Test User",
                    "email": "testuser@example.com"
                },
                "url": f"{repo_url}/commit/1111111111111111111111111111111111111111",
                "added": [],
                "removed": [],
                "modified": ["README.md"]
            }
        ],
        "head_commit": {
            "id": "1111111111111111111111111111111111111111",
            "message": "Test commit",
            "author": {
                "name": "Test User",
                "email": "testuser@example.com"
            }
        }
    }
    
    return payload


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Generate GitHub webhook signature."""
    mac = hmac.new(secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def send_webhook(webhook_url: str, payload: dict, secret: str = None):
    """Send webhook to the server."""
    try:
        # Convert payload to JSON
        payload_json = json.dumps(payload)
        payload_bytes = payload_json.encode('utf-8')
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'X-GitHub-Event': 'push',
            'X-GitHub-Delivery': 'test-delivery-id',
            'User-Agent': 'GitHub-Hookshot/test'
        }
        
        # Add signature if secret provided
        if secret:
            headers['X-Hub-Signature-256'] = sign_payload(payload_bytes, secret)
        
        # Send request
        print(f"Sending webhook to {webhook_url}")
        print(f"Repository: {payload['repository']['html_url']}")
        print(f"Branch: {payload['ref']}")
        print()
        
        response = requests.post(
            webhook_url,
            data=payload_bytes,
            headers=headers,
            timeout=10
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 202:
            print("\n✓ Webhook accepted! Scan has been queued.")
        elif response.status_code == 200:
            print("\n✓ Webhook received but not processed (likely non-subscriber).")
        else:
            print("\n✗ Webhook rejected or error occurred.")
        
        return response.status_code == 202
        
    except requests.exceptions.RequestException as e:
        print(f"Error sending webhook: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test webhook server with mock GitHub payload"
    )
    parser.add_argument(
        '--url',
        default='http://localhost:5000/webhook',
        help='Webhook URL (default: http://localhost:5000/webhook)'
    )
    parser.add_argument(
        '--repo-url',
        default='https://github.com/testowner/testrepo',
        help='Repository URL to test (default: https://github.com/testowner/testrepo)'
    )
    parser.add_argument(
        '--secret',
        help='Webhook secret for signature verification (optional)'
    )
    
    args = parser.parse_args()
    
    # Create mock payload
    payload = create_mock_payload(args.repo_url)
    
    # Send webhook
    success = send_webhook(args.url, payload, args.secret)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
