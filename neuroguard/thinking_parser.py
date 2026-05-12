from typing import Callable


class ThinkingStreamParser:
    """
    Real-time stream splitter for Gemma 4 Thinking Mode output.

    Gemma 4 with <|think|> in the system prompt emits:
        <think>...reasoning...</think>...final response...

    This parser buffers the incoming stream and fires callbacks as each
    region is identified, handling the edge case where tags are split
    across chunk boundaries.
    """

    _OPEN_TAG = "<think>"
    _CLOSE_TAG = "</think>"
    # Max bytes to buffer while waiting to confirm a partial tag
    _MAX_TAG_LEN = max(len(_OPEN_TAG), len(_CLOSE_TAG)) + 2

    def __init__(
        self,
        on_thinking: Callable[[str], None],
        on_response: Callable[[str], None],
    ) -> None:
        self._on_thinking = on_thinking
        self._on_response = on_response
        self._buf = ""
        self._in_think = False
        self._think_done = False

    def feed(self, chunk: str) -> None:
        self._buf += chunk
        self._flush()

    def finalize(self) -> None:
        """Call after the stream ends to flush any remaining buffer."""
        if self._buf:
            target = self._on_thinking if self._in_think else self._on_response
            target(self._buf)
            self._buf = ""

    def _flush(self) -> None:
        while True:
            if self._in_think:
                idx = self._buf.find(self._CLOSE_TAG)
                if idx == -1:
                    # Keep last N chars buffered in case close tag is split
                    safe = max(0, len(self._buf) - self._MAX_TAG_LEN)
                    if safe:
                        self._on_thinking(self._buf[:safe])
                        self._buf = self._buf[safe:]
                    break
                else:
                    self._on_thinking(self._buf[:idx])
                    self._buf = self._buf[idx + len(self._CLOSE_TAG):]
                    self._in_think = False
                    self._think_done = True
            else:
                if not self._think_done:
                    # Haven't seen <think> yet — look for it
                    idx = self._buf.find(self._OPEN_TAG)
                    if idx == -1:
                        # Could be a partial tag at the end
                        safe = max(0, len(self._buf) - self._MAX_TAG_LEN)
                        if safe:
                            # Text before any possible tag goes to response
                            self._on_response(self._buf[:safe])
                            self._buf = self._buf[safe:]
                        break
                    else:
                        # Discard anything before <think> (preamble whitespace etc.)
                        self._buf = self._buf[idx + len(self._OPEN_TAG):]
                        self._in_think = True
                else:
                    # Past </think> — everything is the final response
                    if self._buf:
                        self._on_response(self._buf)
                        self._buf = ""
                    break
