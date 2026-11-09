"""Personnel choices; inspector titles select point teams, never admin routes."""
from typing import NamedTuple


class AccountChoice(NamedTuple):
    label: str
    role: str
    category: str | None
    manager_title: bool = False
    engineering_title: bool = False


ACCOUNT_CHOICES = {
    "safety": AccountChoice("職安巡檢員", "inspector", "safety"),
    "general_executor": AccountChoice("總務執行人員", "executor", "general"),
    "general": AccountChoice("總務巡檢員", "inspector", "general"),
    "general_manager": AccountChoice("總務管理員", "inspector", "general", True),
    "engineering": AccountChoice("工務巡檢員", "inspector", "general", False, True),
    "admin": AccountChoice("系統管理員", "admin", None),
}
ACCOUNT_ROLE_LABELS = {key: choice.label for key, choice in ACCOUNT_CHOICES.items()}
_CHOICE_KEYS = {(c.role, c.category, c.manager_title, c.engineering_title): key for key, c in ACCOUNT_CHOICES.items()}


def account_role_choice(account):
    if account is None:
        return None
    if account.role == "admin":
        return "admin"
    titled = account.role == "inspector" and account.patrol_category == "general" and bool(account.general_manager_title)
    engineering = account.role == "inspector" and account.patrol_category == "general" and bool(account.engineering_inspector_title)
    return _CHOICE_KEYS.get((account.role, account.patrol_category, titled, engineering))


def role_label(account):
    return ACCOUNT_ROLE_LABELS.get(account_role_choice(account), "尚未指派")
