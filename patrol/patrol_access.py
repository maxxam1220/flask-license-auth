"""Category boundaries shared by patrol reads and transactional writes."""


def patrol_scope(user):
    """None = administrator (all); empty = unassigned (none); else one category."""
    if user and user.role == "admin":
        return None
    category = getattr(user, "patrol_category", None)
    return category if user and user.role == "inspector" and category in ("safety", "general") else ""


def can_access_category(user, category):
    scope = patrol_scope(user)
    return scope is None or (bool(scope) and category == scope)


def can_read_inspection(user, record):
    return can_access_category(user, record.category) and (user.role == "admin" or record.user_id == user.id)
