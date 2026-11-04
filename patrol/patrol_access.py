"""Category boundaries shared by patrol reads and transactional writes."""


def patrol_scope(user):
    """None = administrator (all); empty = unassigned (none); else one category."""
    if user and user.role == "admin":
        return None
    category = getattr(user, "patrol_category", None)
    if user and user.role == "executor":
        return "general" if category == "general" else ""
    return category if user and user.role == "inspector" and category in ("safety", "general") else ""


def can_access_category(user, category):
    scope = patrol_scope(user)
    return scope is None or (bool(scope) and category == scope)


def can_view_general_team(user):
    return bool(user and user.role == "inspector" and patrol_scope(user) == "general")


def can_read_inspection(user, record):
    if not can_access_category(user, record.category):
        return False
    if user.role == "admin" or can_view_general_team(user):
        return True
    if record.user_id != user.id:
        return False
    if user.role == "executor":
        # The immutable role-at-submission marker distinguishes a direct visit
        # from receipts this same account submitted as an inspector in the past.
        return (record.executor_visit and record.category == "general" and
                record.workflow_mode == "spot" and record.frequency == "irregular")
    return user.role == "inspector"
