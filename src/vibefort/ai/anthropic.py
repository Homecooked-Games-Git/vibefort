"""Anthropic Claude AI provider."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional

from vibefort.ai.base import AnalysisResult


API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"


class AnthropicProvider:
    """Anthropic Claude provider supporting API key and OAuth token."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        oauth_token: Optional[str] = None,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self.api_key = api_key
        self.oauth_token = oauth_token
        self.model = model

    def is_configured(self) -> bool:
        """Return True if credentials are available."""
        return bool(self.api_key or self.oauth_token)

    def _build_prompt(self, package_or_file: str, code: str, context: str = "") -> str:
        """Build the security analysis prompt."""
        ctx_section = f"\nAdditional context: {context}" if context else ""
        return (
            f"You are a security analyst reviewing code from '{package_or_file}' "
            f"for malicious or dangerous behaviour.{ctx_section}\n\n"
            f"Code to analyse:\n```\n{code}\n```\n\n"
            "Respond with EXACTLY these lines (no markdown, no extra text):\n"
            "RISK: <critical|high|medium|low|safe>\n"
            "EXPLANATION: <one-line explanation>\n"
            "REMEDIATION: <suggested fix or empty>\n"
            "ALTERNATIVE: <safe alternative package or empty>\n"
        )

    def _parse_response(self, text: str) -> AnalysisResult:
        """Parse structured response lines into an AnalysisResult."""
        risk = "unknown"
        explanation = text
        remediation = ""
        alternative = ""

        for line in text.splitlines():
            upper = line.strip().upper()
            if upper.startswith("RISK:"):
                risk = line.split(":", 1)[1].strip().lower()
            elif upper.startswith("EXPLANATION:"):
                explanation = line.split(":", 1)[1].strip()
            elif upper.startswith("REMEDIATION:"):
                remediation = line.split(":", 1)[1].strip()
            elif upper.startswith("ALTERNATIVE:"):
                alternative = line.split(":", 1)[1].strip()

        return AnalysisResult(
            explanation=explanation,
            risk_level=risk,
            remediation=remediation,
            safe_alternative=alternative,
        )

    def _call_api(self, prompt: str) -> str:
        """Send a request to the Anthropic API and return the text response."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        elif self.oauth_token:
            headers["Authorization"] = f"Bearer {self.oauth_token}"

        payload = json.dumps({
            "model": self.model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())

        # Extract text from the first content block
        return body["content"][0]["text"]

    def analyze_package(
        self, package_name: str, suspicious_code: str, context: str = ""
    ) -> AnalysisResult:
        """Analyse suspicious package code via Claude."""
        if not self.is_configured():
            return AnalysisResult(explanation="Provider not configured", risk_level="unknown")
        try:
            prompt = self._build_prompt(package_name, suspicious_code, context)
            text = self._call_api(prompt)
            return self._parse_response(text)
        except Exception as exc:  # noqa: BLE001
            return AnalysisResult(
                explanation=f"Analysis error: {exc}", risk_level="unknown"
            )

    def analyze_code(self, code: str, filename: str = "") -> AnalysisResult:
        """Analyse arbitrary code via Claude."""
        return self.analyze_package(filename or "<inline>", code)
