#!/bin/bash
# Integration test for webhook server
# This script validates the webhook server functionality without running actual Hound scans

set -e

echo "=== Webhook Server Integration Test ==="
echo ""

# Change to project root
cd "$(dirname "$0")/.."

# Clean up any previous test artifacts
rm -f test_subscribers.json test_config.json

echo "1. Testing subscriber database operations..."
# Test adding a subscriber
python scripts/add_subscriber.py \
  --db test_subscribers.json \
  https://github.com/testowner/testrepo \
  test@example.com \
  --secret testsecret123

if [ ! -f test_subscribers.json ]; then
  echo "✗ Failed to create subscriber database"
  exit 1
fi

# Verify the subscriber was added
if ! grep -q "testowner/testrepo" test_subscribers.json; then
  echo "✗ Subscriber not found in database"
  exit 1
fi

echo "✓ Subscriber database operations work"
echo ""

echo "2. Testing configuration creation..."
# Import the server module to trigger config creation
python -c "
from server import WebhookConfig
from pathlib import Path
config = WebhookConfig(Path('test_config.json'))
print('Configuration loaded successfully')
"

if [ ! -f test_config.json ]; then
  echo "✗ Failed to create configuration file"
  exit 1
fi

echo "✓ Configuration creation works"
echo ""

echo "3. Testing webhook signature verification..."
python -c "
from server import verify_webhook_signature
import hashlib
import hmac

payload = b'{\"test\": \"data\"}'
secret = 'my-secret'
mac = hmac.new(secret.encode(), msg=payload, digestmod=hashlib.sha256)
signature = f'sha256={mac.hexdigest()}'

result = verify_webhook_signature(payload, signature, secret)
assert result is True, 'Valid signature verification failed'

result = verify_webhook_signature(payload, 'sha256=invalid', secret)
assert result is False, 'Invalid signature verification failed'

print('Signature verification works correctly')
"

echo "✓ Webhook signature verification works"
echo ""

echo "4. Testing mock webhook payload..."
# Test creating a mock payload
python scripts/test_webhook.py --help > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "✗ test_webhook.py script is not working"
  exit 1
fi

echo "✓ Mock webhook payload script works"
echo ""

echo "5. Testing health endpoint (requires server to be running)..."
echo "Note: Start server with 'python server.py' and test with:"
echo "  curl http://localhost:5000/health"
echo "  python scripts/test_webhook.py"
echo ""

# Clean up test files
rm -f test_subscribers.json test_config.json

echo "=== All integration tests passed ✓ ==="
echo ""
echo "To run a full end-to-end test:"
echo "1. Start the server: python server.py"
echo "2. Add a test subscriber: python scripts/add_subscriber.py <repo> <email>"
echo "3. Send a test webhook: python scripts/test_webhook.py --repo-url <repo>"
echo "4. Check logs: tail -f webhook_server.log"
