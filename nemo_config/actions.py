from nemoguardrails.actions import action

from app.guardrails import inspect_input, inspect_output, redact_sensitive_data


@action(name="detect_prompt_injection")
async def detect_prompt_injection(context: dict) -> bool:
    message = str(context.get("last_user_message", ""))
    return inspect_input(message).allowed


@action(name="sanitize_sensitive_data")
async def sanitize_sensitive_data(context: dict) -> str:
    message = str(context.get("last_user_message", ""))
    return redact_sensitive_data(message)[0]


@action(name="validate_model_output")
async def validate_model_output(context: dict) -> bool:
    message = str(context.get("last_bot_message", ""))
    return inspect_output(message).allowed

