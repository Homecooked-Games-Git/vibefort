"""OAuth browser flow for AI provider authentication."""

import http.server
import threading
import webbrowser
import urllib.parse
import secrets
from typing import Optional

from rich.console import Console

console = Console()

# OAuth endpoints (these will need to be updated when providers publish their OAuth details)
OAUTH_CONFIG = {
    "anthropic": {
        "auth_url": "https://console.anthropic.com/oauth/authorize",
        "token_url": "https://console.anthropic.com/oauth/token",
        "client_id": "vibefort-cli",
        "scope": "api",
    },
    "openai": {
        "auth_url": "https://auth.openai.com/authorize",
        "token_url": "https://auth.openai.com/oauth/token",
        "client_id": "vibefort-cli",
        "scope": "api",
    },
}


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Handle the OAuth callback."""

    token: Optional[str] = None
    error: Optional[str] = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            self.__class__.token = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html><body style="font-family: system-ui; text-align: center; padding: 60px;">
            <h1>&#x2714; Signed in to VibeFort</h1>
            <p>You can close this tab and return to your terminal.</p>
            </body></html>
            """)
        elif "error" in params:
            self.__class__.error = params.get("error_description", params["error"])[0]
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"""
            <html><body style="font-family: system-ui; text-align: center; padding: 60px;">
            <h1>&#x2716; Authentication failed</h1>
            <p>{self.__class__.error}</p>
            </body></html>
            """.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


def run_oauth_flow(provider: str) -> Optional[str]:
    """Run the OAuth browser flow for the given provider.

    Returns the access token/auth code on success, None on failure.
    """
    if provider not in OAUTH_CONFIG:
        console.print(f"[red]Unknown OAuth provider: {provider}[/red]")
        return None

    config = OAUTH_CONFIG[provider]
    state = secrets.token_urlsafe(32)

    # Reset handler state
    OAuthCallbackHandler.token = None
    OAuthCallbackHandler.error = None

    # Start local server on a random port
    server = http.server.HTTPServer(("127.0.0.1", 0), OAuthCallbackHandler)
    port = server.server_address[1]
    redirect_uri = f"http://localhost:{port}/callback"

    # Build auth URL
    params = urllib.parse.urlencode({
        "client_id": config["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": config["scope"],
        "state": state,
    })
    auth_url = f"{config['auth_url']}?{params}"

    console.print(f"\n[bold]Opening browser for {provider.title()} sign-in...[/bold]")
    console.print(f"[dim]If the browser doesn't open, visit:[/dim]")
    console.print(f"[dim]{auth_url}[/dim]\n")

    webbrowser.open(auth_url)

    # Wait for callback with timeout
    server.timeout = 120
    console.print("[dim]Waiting for authentication (timeout: 2 minutes)...[/dim]")

    # Handle requests until we get a token or error or timeout
    while OAuthCallbackHandler.token is None and OAuthCallbackHandler.error is None:
        server.handle_request()
        if OAuthCallbackHandler.token is None and OAuthCallbackHandler.error is None:
            break  # Timeout

    server.server_close()

    if OAuthCallbackHandler.error:
        console.print(f"[red]Authentication failed: {OAuthCallbackHandler.error}[/red]")
        return None

    if OAuthCallbackHandler.token is None:
        console.print("[red]Authentication timed out.[/red]")
        return None

    # In a full implementation, we'd exchange the auth code for an access token here
    # using config["token_url"]. For now, we store the code directly since
    # the exact OAuth details depend on each provider's implementation.
    token = OAuthCallbackHandler.token

    console.print(f"[green]✔[/green] Signed in to {provider.title()}")
    return token
