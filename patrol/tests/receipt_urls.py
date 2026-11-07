"""Ignore only cosmetic voice nonces when comparing persisted receipt targets."""
from urllib.parse import unquote_plus, urlsplit, urlunsplit


def without_voice_feedback(url):
    parts = urlsplit(url)
    query = "&".join(part for part in parts.query.split("&")
                     if unquote_plus(part.split("=", 1)[0]) != "voice_feedback")
    return urlunsplit(parts._replace(query=query))
