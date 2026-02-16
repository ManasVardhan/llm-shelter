"""Example: FastAPI integration with llm-shelter middleware."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from llm_shelter import GuardrailPipeline, InjectionValidator, PIIValidator
from llm_shelter.middleware import ShelterMiddleware
from llm_shelter.pipeline import Action

# --- Build the guardrail pipeline ---
pipeline = (
    GuardrailPipeline()
    .add(PIIValidator(redact=True), Action.REDACT)
    .add(InjectionValidator(), Action.BLOCK)
)

# --- Create FastAPI app with middleware ---
app = FastAPI(title="LLM API with Shelter Guards")
app.add_middleware(ShelterMiddleware, pipeline=pipeline, paths=["/chat"])


class ChatRequest(BaseModel):
    prompt: str


class ChatResponse(BaseModel):
    response: str


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Chat endpoint. Input is automatically guarded by llm-shelter middleware.

    - PII is redacted before reaching this handler
    - Prompt injection attempts are blocked with 422
    """
    # In a real app, you'd call your LLM here
    return ChatResponse(response=f"You said: {request.prompt}")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
