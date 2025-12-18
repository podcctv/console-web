"""
Runtime tweaks to keep gunicorn-compatible imports working across panels.

Some hosting panels pass the Flask entry as ``app/main`` (with a slash) to
Gunicorn. That string is not a valid module path, which leads to
``ModuleNotFoundError: No module named 'app/main'`` before the application even
gets a chance to start. Python automatically imports ``sitecustomize`` on
startup if it is importable from ``sys.path``; we use that hook to register an
alias so the invalid module name resolves to the real Flask module.
"""
from __future__ import annotations

import importlib
import sys


def _ensure_alias(bad_name: str, target: str) -> None:
    """Alias *target* module under *bad_name* if it is importable.

    Gunicorn performs ``importlib.import_module`` with the provided app string;
    populating ``sys.modules`` ahead of time lets that import succeed even when
    the string contains path separators.
    """

    if bad_name in sys.modules:
        return

    try:
        module = importlib.import_module(target)
    except ModuleNotFoundError:
        return

    sys.modules[bad_name] = module


# Support panels that pass ``app/main`` instead of the dotted ``app.main``
_ensure_alias("app/main", "app.main")
