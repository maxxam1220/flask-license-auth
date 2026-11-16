"""Conservative authoring exclusions; never rewrite original OCR evidence.

A pure uncertain placeholder is not usable standard text. This is deliberately
not a logo classifier: the original image and OCR must remain available for
review, and exclusions must be shown to the person approving the standard.
"""


def is_unreadable_placeholder_only(line):
    """Whether a line contains only explicitly unconfirmed □/replacement glyphs.

    Do not exclude meaningful symbols, text with even one readable character,
    or a human-confirmed literal square. This helper never mutates ``line``.
    """
    if not isinstance(line, dict) or not isinstance(line.get("text"), str):
        return False
    if line.get("human_verified") and not line.get("human_uncertain"):
        return False
    if not any(line.get(key) for key in ("uncertain", "ambiguous", "human_uncertain")):
        return False
    text = "".join(line["text"].split())
    return bool(text) and set(text) <= {"□", "\ufffd"}
