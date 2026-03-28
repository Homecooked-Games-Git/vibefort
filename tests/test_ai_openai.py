from vibefort.ai.openai_provider import OpenAIProvider


def test_openai_api_key_configured():
    provider = OpenAIProvider(api_key="sk-test-123")
    assert provider.is_configured()


def test_openai_oauth_configured():
    provider = OpenAIProvider(oauth_token="token-test-456")
    assert provider.is_configured()


def test_openai_unconfigured():
    provider = OpenAIProvider()
    assert not provider.is_configured()
