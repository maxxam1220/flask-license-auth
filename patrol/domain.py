"""Shared patrol labels. Existing integer floor IDs remain stable."""

FLOOR_OPTIONS = [
    (-2, "B2"), (-1, "B1"), (1, "1F"), (11, "1M"), (2, "2F"),
    (3, "3F"), (4, "4F"), (14, "4M"), (5, "5F"), (15, "5M"),
]
FLOOR_LABELS = dict(FLOOR_OPTIONS)
FLOOR_ORDER = {value: index for index, (value, _) in enumerate(FLOOR_OPTIONS)}
CATEGORY_OPTIONS = [("safety", "職安"), ("general", "總務"), ("uncategorized", "未分類")]
CATEGORY_LABELS = dict(CATEGORY_OPTIONS)
FREQUENCY_OPTIONS = [("daily", "每日一次"), ("daily2", "每日兩次（上午／下午）"), ("weekly", "每週一次"),
                     ("monthly", "每月一次"), ("irregular", "不定期")]


def floor_label(value):
    try:
        return FLOOR_LABELS.get(int(value), str(value))
    except (ValueError, TypeError):
        return str(value)


def category_label(value):
    return CATEGORY_LABELS.get(value, "未分類")


def slot_label(value):
    return {"any": "不限時段", "am": "上午", "pm": "下午"}.get(value, str(value))
