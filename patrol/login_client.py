"""Coarse display labels for sign-in history; never identify a physical device."""
import re


def classify_login_client(user_agent, mobile_hint=None):
    ua = (user_agent or "")[:1024].lower()
    if any(tag in ua for tag in ("ipad", "tablet", "kindle", "silk/")):
        device = "tablet"
    elif mobile_hint == "?1" or any(tag in ua for tag in ("iphone", "ipod", "mobile", "windows phone")):
        device = "mobile"
    elif "android" in ua:
        device = "tablet"
    elif any(tag in ua for tag in ("windows nt", "macintosh", "cros", "x11", "linux x86")):
        device = "desktop"
    else:
        device = "unknown"
    for pattern, label in (
        (r"\bline/", "LINE"),
        (r"\b(?:edg|edge|edga|edgios)/", "Edge"),
        (r"\bsamsungbrowser/", "Samsung Internet"),
        (r"\b(?:opr|opera|opios)/", "Opera"),
        (r"\b(?:firefox|fxios)/", "Firefox"),
        (r"; wv\)", "Android WebView"),
        (r"\b(?:chrome|crios)/", "Chrome"),
        (r"\bversion/.*\bsafari/", "Safari"),
    ):
        if re.search(pattern, ua):
            return device, label
    return device, "無法辨識"
