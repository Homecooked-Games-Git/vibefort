import threading
import urllib.request
from vibefort.oauth import OAuthCallbackHandler, run_oauth_flow, OAUTH_CONFIG
import http.server


def test_oauth_callback_handler_success():
    """Test that the callback handler captures the auth code."""
    OAuthCallbackHandler.token = None
    OAuthCallbackHandler.error = None

    server = http.server.HTTPServer(("127.0.0.1", 0), OAuthCallbackHandler)
    port = server.server_address[1]

    def handle():
        server.handle_request()

    t = threading.Thread(target=handle)
    t.start()

    try:
        urllib.request.urlopen(f"http://localhost:{port}/callback?code=test-auth-code-123&state=abc")
    except Exception:
        pass

    t.join(timeout=5)
    server.server_close()

    assert OAuthCallbackHandler.token == "test-auth-code-123"


def test_oauth_callback_handler_error():
    """Test that the callback handler captures errors."""
    OAuthCallbackHandler.token = None
    OAuthCallbackHandler.error = None

    server = http.server.HTTPServer(("127.0.0.1", 0), OAuthCallbackHandler)
    port = server.server_address[1]

    def handle():
        server.handle_request()

    t = threading.Thread(target=handle)
    t.start()

    try:
        urllib.request.urlopen(f"http://localhost:{port}/callback?error=access_denied&error_description=User+denied")
    except Exception:
        pass

    t.join(timeout=5)
    server.server_close()

    assert OAuthCallbackHandler.token is None
    assert OAuthCallbackHandler.error is not None


def test_oauth_config_has_providers():
    assert "anthropic" in OAUTH_CONFIG
    assert "openai" in OAUTH_CONFIG
    for provider in OAUTH_CONFIG.values():
        assert "auth_url" in provider
        assert "token_url" in provider
        assert "client_id" in provider
