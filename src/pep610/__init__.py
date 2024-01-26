"""PEP 610 parser."""

from __future__ import annotations

import hashlib
import json
import sys
import typing as t
from dataclasses import dataclass
from functools import singledispatch
from importlib.metadata import version

if sys.version_info < (3, 9):
    import importlib_resources
else:
    import importlib.resources as importlib_resources

if t.TYPE_CHECKING:
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
    "ArchiveData",
    "ArchiveInfo",
    "DirData",
    "DirInfo",
    "HashData",
    "VCSData",
    "VCSInfo",
    "__version__",
    "read_from_distribution",
    "to_dict",
    "write_to_distribution",
]

SCHEMA_FILE = importlib_resources.files(__package__) / "direct_url.schema.json"
__version__ = version(__package__)


@dataclass
class VCSInfo:
    """VCS information.

    See the :spec:`VCS URLs specification <vcs-urls>`.

    Args:
        vcs: The VCS type.
        commit_id: The exact commit/revision number that was/is to be installed.
        requested_revision: A branch/tag/ref/commit/revision/etc (in a format
            compatible with the VCS).
    """

    vcs: str
    commit_id: str
    requested_revision: str | None = None
    resolved_revision: str | None = None
    resolved_revision_type: str | None = None


@dataclass
class _BaseData:
    """Base direct URL data.

    Args:
        url: The direct URL.
    """

    url: str


@dataclass
class VCSData(_BaseData):
    """VCS direct URL data.

    Args:
        url: The VCS URL.
        vcs_info: VCS information.
    """

    vcs_info: VCSInfo


class HashData(t.NamedTuple):
    """(Deprecated) Archive hash data.

    Args:
        algorithm: The hash algorithm.
        value: The hash value.
    """

    algorithm: str
    value: str


@dataclass
class ArchiveInfo:
    """Archive information.

    See the :spec:`Archive URLs specification <archive-urls>`.

    Args:
        hashes: Dictionary mapping a hash name to a hex encoded digest of the file.

            Any hash algorithm available via :py:mod:`hashlib` (specifically any that can be
            passed to :py:func:`hashlib.new()` and do not require additional parameters) can be used
            as a key for the ``hashes`` dictionary. At least one secure algorithm from
            :py:data:`hashlib.algorithms_guaranteed` SHOULD always be included.
        hash: The archive hash (deprecated).
    """

    hashes: dict[str, str] | None = None
    hash: HashData | None = None

    def has_valid_algorithms(self: ArchiveInfo) -> bool:
        """Has valid archive hashes?

        Checks that the ``hashes`` attribute is not empty and that at least one of the hashes is
        present in :py:data:`hashlib.algorithms_guaranteed`.

        Returns:
            Whether the archive has valid hashes.

        >>> archive_info = ArchiveInfo(
        ...     hashes={
        ...         "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
        ...         "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        ...     },
        ... )
        >>> archive_info.has_valid_algorithms()
        True
        """
        return set(self.all_hashes).intersection(hashlib.algorithms_guaranteed) != set()

    @property
    def all_hashes(self: Self) -> dict[str, str]:
        """All archive hashes.

        Merges the ``hashes`` attribute with the legacy ``hash`` attribute, prioritizing the former.

        Returns:
            All archive hashes.

        >>> archive_info = ArchiveInfo(
        ...     hash=HashData(
        ...         "sha256",
        ...         "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",
        ...     ),
        ...     hashes={
        ...         "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
        ...         "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        ...     },
        ... )
        >>> archive_info.all_hashes
        {'sha256': '1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9', 'md5': 'c4e0f0a1e0a5e708c8e3e3c4cbe2e85f'}
        """  # noqa: E501
        hashes = {}
        if self.hash is not None:
            hashes[self.hash.algorithm] = self.hash.value

        if self.hashes is not None:
            hashes.update(self.hashes)

        return hashes


@dataclass
class ArchiveData(_BaseData):
    """Archive direct URL data.

    Args:
        url: The archive URL.
        archive_info: Archive information.
    """

    archive_info: ArchiveInfo


@dataclass
class DirInfo:
    """Local directory information.

    See the :spec:`Local Directories specification <local-directories>`.

    Args:
        editable: Whether the distribution is installed in editable mode.
    """

    editable: bool | None

    def is_editable(self: Self) -> bool:
        """Distribution is editable?

        ``True`` if the distribution was/is to be installed in editable mode,
        ``False`` otherwise. If absent, default to ``False``

        Returns:
            Whether the distribution is installed in editable mode.

        >>> dir_info = DirInfo(editable=True)
        >>> dir_info.is_editable()
        True

        >>> dir_info = DirInfo(editable=False)
        >>> dir_info.is_editable()
        False

        >>> dir_info = DirInfo(editable=None)
        >>> dir_info.is_editable()
        False
        """
        return self.editable is True


@dataclass
class DirData(_BaseData):
    """Local directory direct URL data.

    Args:
        url: The local directory URL.
        dir_info: Local directory information.
    """

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
    if data.archive_info.hashes is not None:
        archive_info["hashes"] = data.archive_info.hashes

    if data.archive_info.hash is not None:
        archive_info["hash"] = f"{data.archive_info.hash.algorithm}={data.archive_info.hash.value}"

    return {"url": data.url, "archive_info": archive_info}


@to_dict.register(DirData)
def _(data: DirData) -> DirectoryDict:
    dir_info: DirectoryInfoDict = {}
    if data.dir_info.editable is not None:
        dir_info["editable"] = data.dir_info.editable
    return {"url": data.url, "dir_info": dir_info}


def _parse(content: str) -> VCSData | ArchiveData | DirData | None:
    data = json.loads(content)

    if "archive_info" in data:
        hashes = data["archive_info"].get("hashes")
        hash_data = None
        if hash_value := data["archive_info"].get("hash"):
            hash_data = HashData(*hash_value.split("=", 1)) if hash_value else None

        return ArchiveData(
            url=data["url"],
            archive_info=ArchiveInfo(hashes=hashes, hash=hash_data),
        )

    if "dir_info" in data:
        return DirData(
            url=data["url"],
            dir_info=DirInfo(
                editable=data["dir_info"].get("editable"),
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
        dist(importlib_metadata.Distribution): The package distribution.

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
