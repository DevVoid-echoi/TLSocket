import threading
import time

from tlsocket.log_parser.parser import follow


def test_follow_ignores_existing_content_then_yields_new_lines(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text('{"ts": "2026-01-01T00:00:00+00:00", "level": "INFO", "event": "OLD"}\n')

    gen = follow(log_file, poll_interval=0.05)

    results = []
    def _consume_one():
        results.append(next(gen))

    t = threading.Thread(target=_consume_one, daemon=True)
    t.start()
    time.sleep(0.1)

    with open(log_file, "a", encoding="utf-8") as f:
        f.write('{"ts": "2026-01-01T00:00:01+00:00", "level": "INFO", "event": "NEW"}\n')

    t.join(timeout=2)
    assert len(results) == 1
    assert results[0].event_type == "NEW"

def test_follow_skips_malformated_new_lines(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("")

    gen = follow(log_file, poll_interval=0.05)
    results = []
    def _consume_one():
        results.append(next(gen))

    t = threading.Thread(target=_consume_one, daemon=True)
    t.start()
    time.sleep(0.1)

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("something not json\n")
        f.write('{"ts": "2026-01-01T00:00:01+00:00", "level": "INFO", "event": "OK"}\n')

    t.join(timeout=2)
    assert len(results) == 1
    assert results[0].event_type == "OK"