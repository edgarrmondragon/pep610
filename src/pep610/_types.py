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

    #: The resolved revision.
    resolved_revision: str

    #: The resolved revision type.
    resolved_revision_type: str


class VCSDict(t.TypedDict):
    """VCS direct URL data dictionary."""

    #: The VCS URL.
    url: str

    #: VCS information.
    vcs_info: VCSInfoDict


class ArchiveInfoDict(t.TypedDict, total=False):
    """Archive information dictionary."""

    #: The hashes of the archive.
    hashes: dict[str, str]

    #: The hash of the archive (deprecated).
    hash: str


class ArchiveDict(t.TypedDict):
    """Archive direct URL data dictionary."""

    #: The archive URL.
    url: str

    #: Archive information.
    archive_info: ArchiveInfoDict


class DirectoryInfoDict(t.TypedDict, total=False):
    """Local directory information dictionary."""

    #: Whether the directory is editable.
    editable: bool


class DirectoryDict(t.TypedDict):
    """Local directory direct URL data dictionary."""

    #: The local directory URL.
    url: str

    #: Directory information.
    dir_info: DirectoryInfoDict
