from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    import sys

    if sys.version_info < (3, 11):
        from typing_extensions import Required
    else:
        from typing import Required


class VCSInfoDict(t.TypedDict, total=False):
    """VCS information dictionary."""

    #: The VCS type.
    vcs: Required[str]

    #: The commit ID.
    commit_id: Required[str]

    #: The requested revision.
    requested_revision: str

    resolved_revision: str
    resolved_revision_type: str


class ArchiveInfoDict(t.TypedDict, total=False):
    """Archive information dictionary."""

    #: The hashes of the archive.
    hashes: dict[str, str]

    #: The hash of the archive (deprecated).
    hash: str


class DirectoryInfoDict(t.TypedDict, total=False):
    """Local directory information dictionary."""

    #: Whether the directory is editable.
    editable: bool


class DirectUrlDict(t.TypedDict):
    """Direct URL data dictionary."""

    #: The direct URL.
    url: Required[str]

    vcs_info: VCSInfoDict
    archive_info: ArchiveInfoDict
    dir_info: DirectoryInfoDict
