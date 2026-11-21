from rate_limit import (
    get_login_retry_after,
    record_failed_login,
)


def test_rate_limit_expires_after_window():
    client_ip = "rate-limit-window-test"
    for attempt in range(5):
        retry_after = record_failed_login(client_ip, now=100 + attempt)

    assert retry_after > 0
    assert get_login_retry_after(client_ip, now=100 + 4 + 15 * 60) == 0


def test_failed_attempts_below_limit_are_not_blocked():
    client_ip = "rate-limit-under-limit-test"
    for attempt in range(4):
        assert record_failed_login(client_ip, now=200 + attempt) == 0
    assert get_login_retry_after(client_ip, now=204) == 0
