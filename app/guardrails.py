from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardrailDecision:
    allowed: bool
    content: str
    reason: str = "allowed"


INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)?\s*(instructions|prompts|rules)",
        r"(reveal|print|show|repeat).{0,40}(system|developer)\s+prompt",
        r"(jailbreak|do\s+anything\s+now|\bdan\b|developer\s+mode)",
        r"(override|bypass|disable).{0,30}(guardrail|safety|policy|filter)",
        r"(exfiltrate|steal|dump).{0,30}(secret|credential|token|key|environment)",
        r"(read|show|return).{0,30}(/etc/passwd|\.env|environment\s+variable)",
        r"\b(ai|language model)\b.{0,100}\b(biased|bias|political ideology|agenda)\b",
        (
            r"\b(how (do|can|to) i|write|create|make|instructions? for)\b"
            r".{0,50}\b(hack|malware|meth|rob)\b"
        ),
        r"<\s*(system|assistant|developer)\s*>",
    )
)

JAILBREAK_INDICATORS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(act|respond|simulate|roleplay|become|continue)\b.{0,60}\b(as|like|mode|persona|character)\b",
        r"\b(unfiltered|uncensored|unrestricted|amoral|no[ -]?limits|break free)\b",
        r"\b(never|must not|do not|don't|cannot)\b.{0,40}\b(refuse|decline|warn|censor|filter)\b",
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(rule|instruction|policy|guideline|restriction|filter|tos)\b",
        r"\b(no|without|disabled)\b.{0,30}\b(ethics|morals|laws|safety|censorship|filters|restrictions)\b",
        r"\b(make|fabricate)\b.{0,20}\b(up|answer|information)\b",
        r"\b(always|must)\b.{0,35}\b(answer|respond|comply|fulfill|satisfy|follow)\b",
        r"\b(stay|remain)\b.{0,20}\bin character\b",
        r"\b(violate|bypass|ignore)\b.{0,30}\b(ethical|safety|content|policy|standards)\b",
        r"(system announcement|insert prompt here|say anything now|do anything now)",
        r"\b(ai|language model)\b.{0,50}\b(biased|bias|political ideology|agenda)\b",
    )
)

UNSAFE_OPERATION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"disconnect.{0,30}(substation|grid|generator|battery)",
        r"disable.{0,30}(alarm|protection|interlock|safety)",
        r"open.{0,20}(breaker|relay).{0,20}(without|bypass)",
        r"(delete|erase|destroy).{0,30}(telemetry|audit|log|evidence)",
    )
)

SENSITIVE_PATTERNS = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_\-]{16,}\b"),
        "[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        re.compile(r"\b(?:\+?61|0)4\d{8}\b"),
        "[REDACTED_PHONE]",
    ),
)


def redact_sensitive_data(content: str) -> tuple[str, bool]:
    redacted = content
    changed = False
    for pattern, replacement in SENSITIVE_PATTERNS:
        updated = pattern.sub(replacement, redacted)
        changed = changed or updated != redacted
        redacted = updated
    return redacted, changed


def inspect_input(prompt: str, *, maximum_length: int = 4000) -> GuardrailDecision:
    normalized = " ".join(prompt.split())
    if not normalized:
        return GuardrailDecision(False, "", "empty_prompt")
    if len(normalized) > maximum_length:
        return GuardrailDecision(False, "", "prompt_too_long")
    if any(pattern.search(normalized) for pattern in UNSAFE_OPERATION_PATTERNS):
        return GuardrailDecision(False, "", "unsafe_operational_request")
    if any(pattern.search(normalized) for pattern in INJECTION_PATTERNS):
        return GuardrailDecision(False, "", "prompt_injection")
    jailbreak_signals = sum(
        bool(pattern.search(normalized)) for pattern in JAILBREAK_INDICATORS
    )
    if jailbreak_signals >= 2:
        return GuardrailDecision(False, "", "prompt_injection")

    redacted, changed = redact_sensitive_data(normalized)
    return GuardrailDecision(True, redacted, "pii_redacted" if changed else "allowed")


def inspect_output(content: str, *, maximum_length: int = 2000) -> GuardrailDecision:
    if len(content) > maximum_length:
        return GuardrailDecision(False, "", "output_too_long")

    redacted, changed = redact_sensitive_data(content)
    if changed:
        return GuardrailDecision(False, "", "sensitive_output_detected")
    if any(pattern.search(content) for pattern in INJECTION_PATTERNS):
        return GuardrailDecision(False, "", "unsafe_instruction_in_output")
    return GuardrailDecision(True, content)
