#!/usr/bin/env python3
"""
Add a subscriber to the webhook database.

Usage:
    python scripts/add_subscriber.py <repo_url> <email> [--secret <webhook_secret>]
    
Example:
    python scripts/add_subscriber.py https://github.com/owner/repo user@example.com --secret mysecret123
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def add_subscriber(db_path: Path, repo_url: str, email: str, webhook_secret: str = None):
    """Add a new subscriber to the database."""
    try:
        # Load existing database
        if db_path.exists():
            data = json.loads(db_path.read_text())
        else:
            data = {"subscribers": {}}
        
        # Normalize repo URL
        normalized_url = repo_url.rstrip('/').replace('.git', '')
        
        # Check if already exists
        if normalized_url in data["subscribers"]:
            print(f"Warning: Subscriber already exists for {normalized_url}")
            response = input("Overwrite? (y/n): ")
            if response.lower() != 'y':
                print("Aborted.")
                return False
        
        # Add subscriber
        data["subscribers"][normalized_url] = {
            "email": email,
            "webhook_secret": webhook_secret,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "scan_count": 0
        }
        
        # Save database
        db_path.write_text(json.dumps(data, indent=2))
        print(f"✓ Successfully added subscriber: {normalized_url}")
        print(f"  Email: {email}")
        if webhook_secret:
            print(f"  Webhook secret: {webhook_secret}")
        
        return True
        
    except Exception as e:
        print(f"Error adding subscriber: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Add a subscriber to the webhook database"
    )
    parser.add_argument(
        'repo_url',
        help='Repository URL (e.g., https://github.com/owner/repo)'
    )
    parser.add_argument(
        'email',
        help='Subscriber email address'
    )
    parser.add_argument(
        '--secret',
        help='GitHub webhook secret (optional)'
    )
    parser.add_argument(
        '--db',
        default='subscribers.json',
        help='Path to subscriber database (default: subscribers.json)'
    )
    
    args = parser.parse_args()
    
    db_path = Path(args.db)
    success = add_subscriber(db_path, args.repo_url, args.email, args.secret)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
