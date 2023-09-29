from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    import sys

    if sys.version_info <= (3, 10):
        from typing_extensions import Required
    else:
        from typing import Required


class _BaseURLDict(t.TypedDict):
    """Base direct URL data."""

    url: str


class VCSInfoDict(t.TypedDict, total=False):
    """VCS information."""

    vcs: Required[str]
    commit_id: Required[str]
    requested_revision: str
    resolved_revision: str
    resolved_revision_type: str


class VCSDict(t.TypedDict):
    """VCS direct URL data."""

    url: str
    vcs_info: VCSInfoDict


class ArchiveInfoDict(t.TypedDict, total=False):
    """Archive information."""

    hash: str


class ArchiveDict(_BaseURLDict):
    """Archive direct URL data."""

    archive_info: ArchiveInfoDict


class DirectoryInfoDict(t.TypedDict, total=False):
    """Local directory information."""

    editable: bool


class DirectoryDict(_BaseURLDict):
    """Local directory direct URL data."""

    dir_info: DirectoryInfoDict
