"""Category and current point-team boundaries for reads and transactional writes.

The original category on a submitted record remains immutable. Within the
general category, current point ownership controls the handover of all its
history; changing team must not leave old photos or issues visible to the
previous team. Team predicates supplement, never replace, category checks.
"""

from sqlalchemy import false, or_, select

from models import Inspection, PatrolExecution, Point


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


def inspection_team_scope(user):
    """Return the extra general-point scope, not a category authorization.

    None means no additional team restriction (admin, general manager,
    executor or safety inspector). Invalid/unassigned actors return an empty
    scope. General and engineering inspectors each get their own team.
    """
    scope = patrol_scope(user)
    if scope is None:
        return None
    if not scope:
        return ""
    if user.role == "executor" or scope == "safety":
        return None
    manager = bool(getattr(user, "general_manager_title", False))
    engineer = bool(getattr(user, "engineering_inspector_title", False))
    if manager and engineer:
        return ""  # Invalid combinations must never broaden access.
    return None if manager else "engineering" if engineer else "general"


def can_access_point_team(user, point):
    """Check current ownership only; caller still checks the relevant category.

    Historical records call this with their point and authorize the record's
    original category separately. This preserves safety/category history even
    if the point later moves, without leaking the general team's history after
    a general/engineering handover.
    """
    scope = inspection_team_scope(user)
    if scope is None:
        return True
    if not scope or point is None:
        return False
    # Attribute-only historical fixtures predate the additive team column.
    # Persisted rows have a non-null general default enforced by the schema.
    return getattr(point, "inspection_team", "general") == scope


def can_access_point(user, point):
    """Authorize a current point, including direct QR and write requests."""
    return bool(point is not None and can_access_category(user, point.category)
                and (point.category != "general" or can_access_point_team(user, point)))


def apply_point_scope(query, user, model=Point, inspection_team=""):
    """Add current team restrictions to an already category-scoped SQL query.

    ``model`` is Point, Inspection or PatrolExecution; historical rows use an
    EXISTS on Point so every page, CSV and count receives identical ownership
    filtering without multiplying rows. Other categories stay unchanged.
    An explicit team filter is honored only for admin/general-manager actors
    and selects general-category rows of that team. It cannot widen a normal
    inspector's scope. Invalid authorized filter values fail closed.
    """
    if model not in (Point, Inspection, PatrolExecution):
        raise ValueError("Unsupported point scope model")
    scope = inspection_team_scope(user)
    may_filter = bool(user and (user.role == "admin" or (
        user.role == "inspector" and patrol_scope(user) == "general"
        and getattr(user, "general_manager_title", False)
        and not getattr(user, "engineering_inspector_title", False))))
    explicit = bool(inspection_team and may_filter)
    if explicit:
        if inspection_team not in ("general", "engineering"):
            return query.where(false())
        scope = inspection_team
    if scope is None:
        return query
    if not scope:
        return query.where(false())
    team_condition = (Point.inspection_team == scope if model is Point else
        select(Point.id).where(Point.id == model.point_id, Point.inspection_team == scope)
        .correlate(model).exists())
    if explicit:
        return query.where(model.category == "general", team_condition)
    return query.where(or_(model.category != "general", team_condition))


def can_view_general_team(user):
    return bool(user and user.role == "inspector" and patrol_scope(user) == "general")


def can_view_execution_records(user):
    return bool(user and (user.role in ("admin", "executor") or can_view_general_team(user)))


def can_read_inspection(user, record):
    if not can_access_category(user, record.category):
        return False
    if record.category == "general" and not can_access_point_team(user, record.point):
        return False
    if user.role == "admin" or can_view_general_team(user):
        return True
    if record.user_id != user.id:
        return False
    if user.role == "executor":
        # The immutable role-at-submission marker distinguishes a direct visit
        # from receipts this same account submitted as an inspector in the past.
        return (record.executor_visit and record.category == "general" and
                record.workflow_mode == "spot" and
                record.frequency in ("irregular", "three_day", "daily", "weekly_wed", "weekly_fri"))
    return user.role == "inspector"
