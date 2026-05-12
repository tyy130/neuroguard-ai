import os
import time
import warnings
from collections.abc import Iterator

warnings.filterwarnings("ignore", message=".*MALFORMED_RESPONSE.*")

from google import genai
from google.genai import types

from neuroguard.prompts import REVIEW_PROMPT, SYSTEM_PROMPT

# Prefer the larger dense model; fall back to MoE for rate limits / quota
PRIMARY_MODEL = "gemma-4-31b-it"
FALLBACK_MODEL = "gemma-4-26b-a4b-it"

_RETRYABLE_CODES = {429, 503, 500}
_MAX_RETRIES = 3


def _get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "No API key found. Set GEMINI_API_KEY in your environment or .env file."
        )
    return genai.Client(api_key=api_key)


def _is_retryable(exc: Exception) -> bool:
    msg = str(exc)
    return any(str(c) in msg for c in _RETRYABLE_CODES) or "UNAVAILABLE" in msg


def _stream_model(client: genai.Client, model: str, prompt: str) -> Iterator[str]:
    """Inner streaming loop — single model, no retry logic."""
    response = client.models.generate_content_stream(
        model=model,
        contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            max_output_tokens=32768,  # thinking tokens count against this limit
        ),
    )
    in_thought = False
    for chunk in response:
        if chunk.candidates:
            for part in chunk.candidates[0].content.parts:
                is_thought = hasattr(part, "thought") and part.thought
                if is_thought:
                    if not in_thought:
                        yield "<think>"
                        in_thought = True
                    if part.text:
                        yield part.text
                elif part.text:
                    if in_thought:
                        yield "</think>"
                        in_thought = False
                    yield part.text
        elif chunk.text:
            if in_thought:
                yield "</think>"
                in_thought = False
            yield chunk.text
    if in_thought:
        yield "</think>"


def stream_review(code: str, model: str = PRIMARY_MODEL) -> Iterator[str]:
    """
    Stream Gemma 4's response for a code security review.

    Yields raw text chunks containing <think>...</think> reasoning followed
    by the final response. Use ThinkingStreamParser to split them.

    Retries on 429/503 with backoff; falls back to MoE model on persistent failure.
    """
    client = _get_client()
    prompt = REVIEW_PROMPT.format(code=code)
    models_to_try = [model] if model != PRIMARY_MODEL else [PRIMARY_MODEL, FALLBACK_MODEL]

    for attempt_model in models_to_try:
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                yield from _stream_model(client, attempt_model, prompt)
                return
            except Exception as exc:
                if _is_retryable(exc) and attempt < _MAX_RETRIES:
                    wait = 2 ** attempt
                    time.sleep(wait)
                    continue
                if attempt_model == PRIMARY_MODEL and models_to_try[-1] != PRIMARY_MODEL:
                    break  # try fallback model
                raise
