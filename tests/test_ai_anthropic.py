from vibefort.ai.anthropic import AnthropicProvider


def test_anthropic_api_key_configured():
    provider = AnthropicProvider(api_key="sk-ant-test-123")
    assert provider.is_configured()


def test_anthropic_oauth_configured():
    provider = AnthropicProvider(oauth_token="token-test-456")
    assert provider.is_configured()


def test_anthropic_unconfigured():
    provider = AnthropicProvider()
    assert not provider.is_configured()


def test_anthropic_build_prompt():
    provider = AnthropicProvider(api_key="sk-ant-test")
    prompt = provider._build_prompt("evil.py", "import os; os.system('rm -rf /')")
    assert "evil.py" in prompt
    assert "os.system" in prompt
