"""PEP 610 parser."""

from __future__ import annotations

import json
import typing as t
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

if t.TYPE_CHECKING:
    from importlib.metadata import Distribution
    from os import PathLike

__version__ = version(__package__)


class PEP610Error(Exception):
    """Base exception for PEP 610 errors."""


@dataclass
class VCSInfo:
    """VCS information."""

    vcs: str
    commit_id: str
    requested_revision: str | None = None
    resolved_revision: str | None = None
    resolved_revision_type: str | None = None


@dataclass
class VCSData:
    """VCS direct URL data."""

    url: str
    vcs_info: VCSInfo


class HashData(t.NamedTuple):
    """Archive hash data."""

    algorithm: str
    value: str


@dataclass
class ArchiveInfo:
    """Archive information."""

    hash: HashData | None  # noqa: A003


@dataclass
class ArchiveData:
    """Archive direct URL data."""

    url: str
    archive_info: ArchiveInfo


@dataclass
class DirInfo:
    """Local directory information."""

    editable: bool


@dataclass
class DirData:
    """Local directory direct URL data."""

    url: str
    dir_info: DirInfo


def parse(path: PathLike[str]) -> VCSData | ArchiveData | DirData:
    """Parse a PEP 610 file.

    Args:
        path: The path to the PEP 610 file.

    Returns:
        The parsed PEP 610 file.

    Raises:
        PEP610Error: If the PEP 610 file is invalid.
    """
    with Path(path).open() as f:
        try:
            result = _parse(f.read())
        except json.JSONDecodeError as e:
            msg = f"Failed to parse {path}"
            raise PEP610Error(msg) from e

    if result is None:
        errmsg = f"Unknown PEP 610 file format: {path}"
        raise PEP610Error(errmsg)

    return result


def _parse(content: str) -> VCSData | ArchiveData | DirData | None:
    data = json.loads(content)

    if "archive_info" in data:
        hash_value = data["archive_info"].get("hash")
        hash_data = HashData(*hash_value.split("=", 1)) if hash_value else None
        return ArchiveData(
            url=data["url"],
            archive_info=ArchiveInfo(hash=hash_data),
        )

    if "dir_info" in data:
        return DirData(
            url=data["url"],
            dir_info=DirInfo(
                editable=data["dir_info"].get("editable", False),
            ),
        )

    if "vcs_info" in data:
        return VCSData(
            url=data["url"],
            vcs_info=VCSInfo(
                vcs=data["vcs_info"]["vcs"],
                commit_id=data["vcs_info"]["commit_id"],
                requested_revision=data["vcs_info"].get("requested_revision"),
                resolved_revision=data["vcs_info"].get("resolved_revision"),
                resolved_revision_type=data["vcs_info"].get("resolved_revision_type"),
            ),
        )

    return None


def read_from_distribution(dist: Distribution) -> VCSData | ArchiveData | DirData | None:
    """Read the package data for a given package.

    Args:
        dist: The package distribution.

    Returns:
        The parsed PEP 610 file.
    """
    if contents := dist.read_text("direct_url.json"):
        return _parse(contents)

    return None
