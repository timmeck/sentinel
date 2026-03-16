"""Tests for web crawler module."""

from src.scanner.crawler import LinkParser


def test_link_parser_extracts_links():
    parser = LinkParser("https://example.com/page")
    parser.feed('<a href="/about">About</a><a href="https://other.com">External</a>')
    assert "https://example.com/about" in parser.links
    assert "https://other.com" in parser.links


def test_link_parser_extracts_forms():
    parser = LinkParser("https://example.com")
    parser.feed('''
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="hidden" name="csrf_token" value="abc123">
        </form>
    ''')
    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form["action"] == "https://example.com/login"
    assert form["method"] == "POST"
    assert len(form["inputs"]) == 3


def test_link_parser_extracts_scripts():
    parser = LinkParser("https://example.com")
    parser.feed('<script src="/js/app.js"></script><script src="https://cdn.com/lib.js"></script>')
    assert "https://example.com/js/app.js" in parser.scripts
    assert "https://cdn.com/lib.js" in parser.scripts


def test_link_parser_ignores_anchors():
    parser = LinkParser("https://example.com")
    parser.feed('<a href="#">Skip</a><a href="javascript:void(0)">JS</a><a href="mailto:test@test.com">Mail</a>')
    assert len(parser.links) == 0


def test_link_parser_relative_urls():
    parser = LinkParser("https://example.com/page/sub")
    parser.feed('<a href="../other">Other</a>')
    assert "https://example.com/other" in parser.links
