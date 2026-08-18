from __future__ import annotations


class GridAssistant:
    """Deterministic stand-in for a hosted LLM used in repeatable security tests."""

    def generate(self, prompt: str) -> str:
        lowered = prompt.lower()
        if "battery" in lowered:
            return (
                "Battery storage can absorb surplus renewable generation and discharge "
                "during periods of high demand, subject to operator-approved constraints."
            )
        if "solar" in lowered or "renewable" in lowered:
            return (
                "DERMS coordinates forecasts, network constraints and distributed resources "
                "to help operators integrate variable renewable generation."
            )
        if "security" in lowered or "secure" in lowered:
            return (
                "Use least privilege, authenticated change control, network segmentation, "
                "continuous monitoring and tested recovery procedures."
            )
        return (
            "I can provide high-level information about renewable integration, battery "
            "storage, grid software and defensive cybersecurity controls."
        )

