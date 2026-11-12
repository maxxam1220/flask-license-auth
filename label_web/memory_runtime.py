"""Conservative OCR budgets selected from the smallest finite cgroup limit."""
import math


MIB = 1024 * 1024


def memory_setting(value, name, minimum, maximum):
    """Accept explicit integer settings without exposing their supplied value."""
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"Invalid {name} memory setting")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {name} memory setting") from None
    if not minimum <= parsed <= maximum:
        raise ValueError(f"Invalid {name} memory setting")
    return parsed


def select_memory_policy(limit_bytes=None, worker_mb=None, reserve_mb=None):
    """Environment/configuration can only tighten the capacity-based budgets.

    The legacy 512 MiB service keeps its 360/96 MiB limits. Larger services reserve
    one eighth for bursts (96 to 512 MiB) and cap one serial worker at 1280 MiB.
Unknown capacity never authorizes a larger worker. All ancestor usage counters
must still be enforced separately by the caller.
"""
    worker_mb = memory_setting(worker_mb, "worker", 128, 1280)
    reserve_mb = memory_setting(reserve_mb, "reserve", 96, 512)
    capacity = int(limit_bytes // MIB) if limit_bytes is not None else 512
    if capacity < 280:
        raise ValueError("Insufficient monitored memory capacity")
    automatic_reserve = max(96, min(512, math.ceil(capacity / 128) * 16))
    automatic_worker = (min(360, capacity - automatic_reserve - 56) if capacity <= 512
                        else min(1280, max(360, (capacity * 5 // 8) // 16 * 16)))
    reserve = reserve_mb if reserve_mb is not None else automatic_reserve
    if reserve < automatic_reserve:
        raise ValueError("Reserved memory cannot be below the safe capacity policy")
    # Explicitly increasing the reserve may also lower the automatic worker cap.
    worker_ceiling = min(automatic_worker, capacity - reserve - max(56, capacity // 16))
    worker = worker_mb if worker_mb is not None else worker_ceiling
    if not 128 <= worker <= worker_ceiling:
        raise ValueError("OCR worker memory exceeds the safe capacity policy")
    return {"policy": "cgroup_capacity" if limit_bytes is not None else "conservative_fallback",
            "service_limit_mb": capacity if limit_bytes is not None else None,
            "worker_limit_mb": worker, "reserve_mb": reserve,
            "service_stop_mb": capacity - reserve if limit_bytes is not None else None,
            "det_limit": 1600 if worker >= 768 else 1280,
            "configured": worker_mb is not None or reserve_mb is not None}
