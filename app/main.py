from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from app.guardrails import inspect_input, inspect_output
from app.model import GridAssistant

logger = logging.getLogger("guardrail.audit")
logging.basicConfig(level=logging.INFO, format="%(message)s")


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1, max_length=8000)
    context: dict[str, Any] | None = None


class ChatResponse(BaseModel):
    response: str
    blocked: bool
    reason: str
    request_id: str


app = FastAPI(
    title="Grid AI Guardrail Gateway",
    version="1.0.0",
    description="Input and output security controls for an energy-domain AI assistant.",
    docs_url=None,
    redoc_url=None,
)
model = GridAssistant()


def audit_event(request_id: str, prompt: str, decision: str) -> None:
    prompt_fingerprint = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
    logger.info(
        json.dumps(
            {
                "event": "guardrail_decision",
                "request_id": request_id,
                "prompt_fingerprint": prompt_fingerprint,
                "decision": decision,
            },
            separators=(",", ":"),
        )
    )


def refusal(reason: str) -> str:
    if reason == "unsafe_operational_request":
        return (
            "I cannot provide instructions that bypass operational safeguards. "
            "Use an authorised engineering change-control process."
        )
    return "I cannot comply with that request because it conflicts with the security policy."


def process_prompt(prompt: str) -> ChatResponse:
    request_id = str(uuid4())
    input_decision = inspect_input(prompt)
    if not input_decision.allowed:
        audit_event(request_id, prompt, input_decision.reason)
        return ChatResponse(
            response=refusal(input_decision.reason),
            blocked=True,
            reason=input_decision.reason,
            request_id=request_id,
        )

    candidate = model.generate(input_decision.content)
    output_decision = inspect_output(candidate)
    if not output_decision.allowed:
        audit_event(request_id, prompt, output_decision.reason)
        return ChatResponse(
            response="The generated response was withheld by the output security policy.",
            blocked=True,
            reason=output_decision.reason,
            request_id=request_id,
        )

    audit_event(request_id, prompt, input_decision.reason)
    return ChatResponse(
        response=output_decision.content,
        blocked=False,
        reason=input_decision.reason,
        request_id=request_id,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    return process_prompt(request.prompt)


@app.post("/v1/garak")
def garak_endpoint(request: ChatRequest) -> dict[str, str]:
    result = process_prompt(request.prompt)
    return {"response": result.response}

