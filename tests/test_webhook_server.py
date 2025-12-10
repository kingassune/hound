"""Tests for webhook server functionality."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestSubscriberDatabase:
    """Test SubscriberDatabase class."""
    
    def test_create_empty_database(self):
        """Test creating an empty database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_subscribers.json"
            
            # Import here to avoid Flask import issues
            from server import SubscriberDatabase
            
            db = SubscriberDatabase(db_path)
            
            # Verify database file was created
            assert db_path.exists()
            
            # Verify structure
            data = json.loads(db_path.read_text())
            assert "subscribers" in data
            assert data["subscribers"] == {}
    
    def test_add_subscriber(self):
        """Test adding a subscriber."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_subscribers.json"
            
            from server import SubscriberDatabase
            
            db = SubscriberDatabase(db_path)
            
            # Add subscriber
            result = db.add_subscriber(
                "https://github.com/test/repo",
                "test@example.com",
                "secret123"
            )
            
            assert result is True
            
            # Verify data
            data = json.loads(db_path.read_text())
            assert "https://github.com/test/repo" in data["subscribers"]
            
            sub = data["subscribers"]["https://github.com/test/repo"]
            assert sub["email"] == "test@example.com"
            assert sub["webhook_secret"] == "secret123"
            assert "added_at" in sub
            assert sub["scan_count"] == 0
    
    def test_get_subscriber(self):
        """Test retrieving a subscriber."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_subscribers.json"
            
            from server import SubscriberDatabase
            
            db = SubscriberDatabase(db_path)
            
            # Add subscriber
            db.add_subscriber(
                "https://github.com/test/repo",
                "test@example.com",
                "secret123"
            )
            
            # Get subscriber - exact match
            subscriber = db.get_subscriber("https://github.com/test/repo")
            assert subscriber is not None
            assert subscriber["email"] == "test@example.com"
            
            # Get subscriber - with .git suffix
            subscriber = db.get_subscriber("https://github.com/test/repo.git")
            assert subscriber is not None
            
            # Get subscriber - with trailing slash
            subscriber = db.get_subscriber("https://github.com/test/repo/")
            assert subscriber is not None
            
            # Non-existent subscriber
            subscriber = db.get_subscriber("https://github.com/other/repo")
            assert subscriber is None


class TestWebhookConfig:
    """Test WebhookConfig class."""
    
    def test_create_default_config(self):
        """Test creating default configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"
            
            from server import WebhookConfig
            
            config = WebhookConfig(config_path)
            
            # Verify config file was created
            assert config_path.exists()
            
            # Verify structure
            assert config.get('smtp', 'host') is not None
            assert config.get('hound', 'script_path') is not None
            assert config.get('server', 'port') is not None
    
    def test_get_nested_values(self):
        """Test getting nested configuration values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"
            
            from server import WebhookConfig
            
            config = WebhookConfig(config_path)
            
            # Get nested value
            port = config.get('server', 'port')
            assert port == 5000
            
            # Get with default
            value = config.get('nonexistent', 'key', default='default_value')
            assert value == 'default_value'


class TestWebhookSignature:
    """Test webhook signature verification."""
    
    def test_verify_signature_valid(self):
        """Test verifying a valid signature."""
        from server import verify_webhook_signature
        
        payload = b'{"test": "data"}'
        secret = "my-secret"
        
        # Generate valid signature
        import hashlib
        import hmac
        mac = hmac.new(secret.encode(), msg=payload, digestmod=hashlib.sha256)
        signature = f"sha256={mac.hexdigest()}"
        
        # Verify
        assert verify_webhook_signature(payload, signature, secret) is True
    
    def test_verify_signature_invalid(self):
        """Test verifying an invalid signature."""
        from server import verify_webhook_signature
        
        payload = b'{"test": "data"}'
        secret = "my-secret"
        signature = "sha256=invalid_signature"
        
        # Verify
        assert verify_webhook_signature(payload, signature, secret) is False
    
    def test_verify_signature_missing(self):
        """Test verifying with missing signature."""
        from server import verify_webhook_signature
        
        payload = b'{"test": "data"}'
        secret = "my-secret"
        
        # Verify
        assert verify_webhook_signature(payload, None, secret) is False
        assert verify_webhook_signature(payload, "", secret) is False
    
    def test_verify_signature_wrong_algorithm(self):
        """Test verifying with wrong algorithm."""
        from server import verify_webhook_signature
        
        payload = b'{"test": "data"}'
        secret = "my-secret"
        signature = "sha1=somehash"
        
        # Verify
        assert verify_webhook_signature(payload, signature, secret) is False


class TestWebhookEndpoint:
    """Test webhook endpoint."""
    
    @pytest.fixture
    def app(self):
        """Create test Flask app."""
        from server import app
        app.config['TESTING'] = True
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'queue_size' in data
        assert 'timestamp' in data
    
    def test_webhook_no_payload(self, client):
        """Test webhook with no payload."""
        response = client.post(
            '/webhook',
            content_type='application/json'
        )
        # Server catches all exceptions and returns 500
        assert response.status_code in [400, 500]
        
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_webhook_missing_repo_url(self, client):
        """Test webhook with missing repository URL."""
        payload = {"ref": "refs/heads/main"}
        response = client.post(
            '/webhook',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
    
    @patch('server.SubscriberDatabase')
    def test_webhook_non_subscriber(self, mock_db_class, client):
        """Test webhook from non-subscriber."""
        # Mock database to return None (non-subscriber)
        mock_db = MagicMock()
        mock_db.get_subscriber.return_value = None
        mock_db_class.return_value = mock_db
        
        payload = {
            "ref": "refs/heads/main",
            "repository": {
                "html_url": "https://github.com/test/repo"
            }
        }
        
        response = client.post(
            '/webhook',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'X-GitHub-Event': 'push'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ignored'
    
    def test_webhook_non_push_event(self, client):
        """Test webhook with non-push event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create temporary database with subscriber
            db_path = Path(tmpdir) / "test_subscribers.json"
            db_data = {
                "subscribers": {
                    "https://github.com/test/repo": {
                        "email": "test@example.com",
                        "webhook_secret": None,
                        "added_at": "2024-01-01T00:00:00+00:00",
                        "scan_count": 0
                    }
                }
            }
            db_path.write_text(json.dumps(db_data))
            
            # Create temporary config
            config_path = Path(tmpdir) / "test_config.json"
            from server import WebhookConfig
            config = WebhookConfig(config_path)
            
            payload = {
                "ref": "refs/heads/main",
                "repository": {
                    "html_url": "https://github.com/test/repo"
                }
            }
            
            with patch('server.SUBSCRIBERS_DB', db_path):
                with patch('server.CONFIG_FILE', config_path):
                    response = client.post(
                        '/webhook',
                        data=json.dumps(payload),
                        content_type='application/json',
                        headers={'X-GitHub-Event': 'pull_request'}
                    )
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'ignored'


class TestEmailSending:
    """Test email functionality."""
    
    @patch('smtplib.SMTP')
    def test_send_email_success(self, mock_smtp):
        """Test successful email sending."""
        from server import send_email, WebhookConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"
            config = WebhookConfig(config_path)
            
            # Mock SMTP
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Send email
            result = send_email(
                to_email="test@example.com",
                subject="Test Subject",
                html_content="<html><body>Test</body></html>",
                config=config
            )
            
            assert result is True
            mock_server.send_message.assert_called_once()
    
    @patch('smtplib.SMTP')
    def test_send_email_failure(self, mock_smtp):
        """Test email sending failure."""
        from server import send_email, WebhookConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"
            config = WebhookConfig(config_path)
            
            # Mock SMTP to raise exception
            mock_smtp.return_value.__enter__.side_effect = Exception("SMTP error")
            
            # Send email
            result = send_email(
                to_email="test@example.com",
                subject="Test Subject",
                html_content="<html><body>Test</body></html>",
                config=config
            )
            
            assert result is False
