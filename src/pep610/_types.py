from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
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


class DirectUrlDict(t.TypedDict, total=False):
    """Direct URL data dictionary."""

    #: The direct URL.
    url: Required[str]

    #: A directory path, relative to the root of the VCS repository, source archive or local
    #: directory, to specify where pyproject.toml or setup.py is located.
    subdirectory: str

    #: VCS repository details
    vcs_info: VCSInfoDict

    #: Archive URL details
    archive_info: ArchiveInfoDict

    #: Local directory details
    dir_info: DirectoryInfoDict
