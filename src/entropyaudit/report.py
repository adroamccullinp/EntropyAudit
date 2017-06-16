"""Report rendering for entropyaudit.

Output is line oriented so results diff cleanly in git, and it is deterministic:
the same input tree always yields byte identical output. Findings are sorted by
path, line, column, then rule id before rendering.
"""

from __future__ import annotations

