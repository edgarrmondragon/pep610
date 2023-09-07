"""PEP 610 parser."""

from __future__ import annotations

import json
import typing as t
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

if t.TYPE_CHECKING:
    import sys
    from importlib.metadata import Distribution
    from os import PathLike

    if sys.version_info <= (3, 10):
        from typing_extensions import Self
    else:
        from typing import Self

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
class _BaseData:
    """Base direct URL data."""

    url: str


@dataclass
class VCSData(_BaseData):
    """VCS direct URL data."""

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
class ArchiveData(_BaseData):
    """Archive direct URL data."""

    archive_info: ArchiveInfo


@dataclass
class DirInfo:
    """Local directory information."""

    _editable: bool | None

    @property
    def editable(self: Self) -> bool:
        """Whether the directory is editable."""
        return self._editable is True

    @editable.setter
    def editable(self: Self, value: bool | None) -> None:
        """Set whether the directory is editable."""
        self._editable = value


@dataclass
class DirData(_BaseData):
    """Local directory direct URL data."""

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


def to_dict(data: VCSData | ArchiveData | DirData) -> dict[str, t.Any]:
    """Convert the parsed data to a dictionary.

    Args:
        data: The parsed data.

    Returns:
        The data as a dictionary.
    """
    result: dict[str, t.Any] = {"url": data.url}
    if isinstance(data, VCSData):
        vcs_info = {
            "vcs": data.vcs_info.vcs,
            "commit_id": data.vcs_info.commit_id,
        }
        if data.vcs_info.requested_revision is not None:
            vcs_info["requested_revision"] = data.vcs_info.requested_revision
        if data.vcs_info.resolved_revision is not None:
            vcs_info["resolved_revision"] = data.vcs_info.resolved_revision
        if data.vcs_info.resolved_revision_type is not None:
            vcs_info["resolved_revision_type"] = data.vcs_info.resolved_revision_type
        result["vcs_info"] = vcs_info

    elif isinstance(data, ArchiveData):
        result["archive_info"] = {}
        if data.archive_info.hash is not None:
            result["archive_info"][
                "hash"
            ] = f"{data.archive_info.hash.algorithm}={data.archive_info.hash.value}"

    elif isinstance(data, DirData):
        result["dir_info"] = {}
        if data.dir_info._editable is not None:  # noqa: SLF001
            result["dir_info"]["editable"] = data.dir_info._editable  # noqa: SLF001

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
                _editable=data["dir_info"].get("editable"),
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
