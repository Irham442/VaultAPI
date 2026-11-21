"""Small in-memory rate limiter for failed login attempts."""

from collections import deque
from math import ceil
from threading import Lock
from time import monotonic


MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60

_failed_attempts: dict[str, deque[float]] = {}
_lock = Lock()


def _remove_expired_attempts(client_ip: str, now: float) -> deque[float]:
    attempts = _failed_attempts.get(client_ip)
    if attempts is None:
        return deque()
    cutoff = now - LOGIN_ATTEMPT_WINDOW_SECONDS
    while attempts and attempts[0] <= cutoff:
        attempts.popleft()
    if not attempts:
        _failed_attempts.pop(client_ip, None)
        return deque()
    return attempts


def _retry_after(attempts: deque[float], now: float) -> int:
    if len(attempts) < MAX_FAILED_LOGIN_ATTEMPTS:
        return 0
    return max(
        1,
        ceil(LOGIN_ATTEMPT_WINDOW_SECONDS - (now - attempts[0])),
    )


def get_login_retry_after(client_ip: str, now: float | None = None) -> int:
    """Return remaining lockout seconds, or zero when login is allowed."""
    current_time = monotonic() if now is None else now
    with _lock:
        attempts = _remove_expired_attempts(client_ip, current_time)
        return _retry_after(attempts, current_time)


def record_failed_login(client_ip: str, now: float | None = None) -> int:
    """Record a failed login and return lockout seconds if the limit is reached."""
    current_time = monotonic() if now is None else now
    with _lock:
        attempts = _remove_expired_attempts(client_ip, current_time)
        if client_ip not in _failed_attempts:
            _failed_attempts[client_ip] = attempts
        attempts.append(current_time)
        return _retry_after(attempts, current_time)


def clear_failed_logins(client_ip: str) -> None:
    """Reset the IP's failed-attempt counter after a successful login."""
    with _lock:
        _failed_attempts.pop(client_ip, None)
