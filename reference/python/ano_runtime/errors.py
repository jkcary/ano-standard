from __future__ import annotations


class ANOError(RuntimeError):
    """Machine-readable runtime failure."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }


class InvalidTransition(ANOError):
    def __init__(self, current: str, event: str) -> None:
        super().__init__(
            "INVALID_STATE_TRANSITION",
            f"No transition from {current!r} for event {event!r}",
        )

