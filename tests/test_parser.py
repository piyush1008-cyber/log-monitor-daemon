"""Tests for log parsing functionality."""

from datetime import datetime
from src.parser import parse_line, parse_timestamp


def test_parse_valid_combined_log():
    raw = '127.0.0.1 - frank [10/Oct/2026:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/4.08"'
    record = parse_line(raw)

    assert record is not None
    assert record.ip == "127.0.0.1"
    assert record.user == "frank"
    assert record.method == "GET"
    assert record.path == "/apache_pb.gif"
    assert record.protocol == "HTTP/1.0"
    assert record.status == 200
    assert record.bytes_sent == 2326
    assert record.referer == "http://example.com/start.html"
    assert record.is_error is False
    assert record.is_server_error is False


def test_parse_error_statuses():
    raw_404 = '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /not-found HTTP/1.1" 404 180 "-" "-"'
    raw_500 = '10.0.0.1 - - [10/Oct/2026:13:55:37 +0000] "POST /api/crash HTTP/1.1" 500 450 "-" "-"'

    rec_404 = parse_line(raw_404)
    rec_500 = parse_line(raw_500)

    assert rec_404 is not None and rec_404.is_client_error and rec_404.is_error
    assert not rec_404.is_server_error

    assert rec_500 is not None and rec_500.is_server_error and rec_500.is_error
    assert not rec_500.is_client_error


def test_parse_invalid_or_comment_line():
    assert parse_line("") is None
    assert parse_line("# This is a comment") is None
    assert parse_line("Malformed garbage line") is None
