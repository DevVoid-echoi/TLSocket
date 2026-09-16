import time

from tlsocket.security.rate_limiter import SlidingWindowLimiter


def test_allows_up_to_max_events():
    limiter = SlidingWindowLimiter(max_events=3, window_seconds=60)
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is False

def test_keys_are_independent():
    limiter = SlidingWindowLimiter(max_events=1, window_seconds=60)
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is False
    assert limiter.allow("2.2.2.2") is True

def test_old_events_expire_out_of_window():
    limiter = SlidingWindowLimiter(max_events=1, window_seconds=60)
    limiter.allow("1.1.1.1")
    limiter._history["1.1.1.1"] = [time.monotonic() - 61]
    assert limiter.allow("1.1.1.1") is True

def test_denied_events_is_not_recorded():
    limiter = SlidingWindowLimiter(max_events=1, window_seconds=60)
    limiter.allow("1.1.1.1")
    assert limiter.allow("1.1.1.1") is False
    assert len(limiter._history["1.1.1.1"]) == 1

def test_reset_clears_all_keys():
    limiter = SlidingWindowLimiter(max_events=1, window_seconds=60)
    limiter.allow("1.1.1.1")
    limiter.allow("2.2.2.2")
    limiter.reset()
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("2.2.2.2") is True

def test_forget_clears_only_one_key():
    limiter = SlidingWindowLimiter(max_events=1, window_seconds=60)
    limiter.allow("1.1.1.1")
    limiter.allow("2.2.2.2")
    limiter.forget("1.1.1.1")
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("2.2.2.2") is False
                  


