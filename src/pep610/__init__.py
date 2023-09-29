"""PEP 610 parser."""

from __future__ import annotations

import json
import typing as t
from dataclasses import dataclass
from functools import singledispatch
from importlib.metadata import version

if t.TYPE_CHECKING:
    import sys
    from importlib.metadata import Distribution, PathDistribution

    if sys.version_info <= (3, 10):
        from typing_extensions import Self
    else:
        from typing import Self

    from pep610._types import (
        ArchiveDict,
        ArchiveInfoDict,
        DirectoryDict,
        DirectoryInfoDict,
        VCSDict,
        VCSInfoDict,
    )

__all__ = [
    "VCSInfo",
    "VCSData",
    "HashData",
    "ArchiveInfo",
    "ArchiveData",
    "DirInfo",
    "DirData",
    "to_dict",
    "read_from_distribution",
    "write_to_distribution",
    "__version__",
]

__version__ = version(__package__)


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
    def editable(self: Self) -> bool | None:
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


@singledispatch
def to_dict(data) -> dict[str, t.Any]:  # noqa: ANN001
    """Convert the parsed data to a dictionary.

    Args:
        data: The parsed data.

    Raises:
        NotImplementedError: If the data type is not supported.
    """
    message = f"Cannot serialize unknown direct URL data of type {type(data)}"
    raise NotImplementedError(message)


@to_dict.register(VCSData)
def _(data: VCSData) -> VCSDict:
    vcs_info: VCSInfoDict = {
        "vcs": data.vcs_info.vcs,
        "commit_id": data.vcs_info.commit_id,
    }
    if data.vcs_info.requested_revision is not None:
        vcs_info["requested_revision"] = data.vcs_info.requested_revision
    if data.vcs_info.resolved_revision is not None:
        vcs_info["resolved_revision"] = data.vcs_info.resolved_revision
    if data.vcs_info.resolved_revision_type is not None:
        vcs_info["resolved_revision_type"] = data.vcs_info.resolved_revision_type

    return {"url": data.url, "vcs_info": vcs_info}


@to_dict.register(ArchiveData)
def _(data: ArchiveData) -> ArchiveDict:
    archive_info: ArchiveInfoDict = {}
    if data.archive_info.hash is not None:
        archive_info["hash"] = f"{data.archive_info.hash.algorithm}={data.archive_info.hash.value}"

    return {"url": data.url, "archive_info": archive_info}


@to_dict.register(DirData)
def _(data: DirData) -> DirectoryDict:
    dir_info: DirectoryInfoDict = {}
    if data.dir_info._editable is not None:  # noqa: SLF001
        dir_info["editable"] = data.dir_info._editable  # noqa: SLF001
    return {"url": data.url, "dir_info": dir_info}


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


def write_to_distribution(dist: PathDistribution, data: dict) -> int:
    """Write the direct URL data to a distribution.

    Args:
        dist: The distribution.
        data: The direct URL data.

    Returns:
        The number of bytes written.
    """
    return dist._path.joinpath(  # type: ignore[attr-defined]  # noqa: SLF001
        "direct_url.json",
    ).write_text(json.dumps(data))
