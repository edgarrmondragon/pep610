"""PEP 610 parser."""

from __future__ import annotations

import abc
import hashlib
import json
import typing as t
from dataclasses import dataclass
from functools import singledispatch
from importlib.metadata import distribution, version

if t.TYPE_CHECKING:
    import sys
    from importlib.metadata import Distribution, PathDistribution

    if sys.version_info < (3, 11):
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

__version__ = version(__package__)

DIRECT_URL_METADATA_NAME = "direct_url.json"


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

    def to_dict(self) -> VCSInfoDict:
        """Convert the VCS data to a dictionary.

        Returns:
            The VCS data as a dictionary.

        .. code-block:: pycon

            >>> vcs_info = VCSInfo(
            ...     vcs="git",
            ...     commit_id="4f42225e91a0be634625c09e84dd29ea82b85e27",
            ...     requested_revision="main",
            ... )
            >>> vcs_info.to_dict()
            {'vcs': 'git', 'commit_id': '4f42225e91a0be634625c09e84dd29ea82b85e27', 'requested_revision': 'main'}
        """  # noqa: E501
        vcs_info: VCSInfoDict = {
            "vcs": self.vcs,
            "commit_id": self.commit_id,
        }
        if self.requested_revision is not None:
            vcs_info["requested_revision"] = self.requested_revision
        if self.resolved_revision is not None:
            vcs_info["resolved_revision"] = self.resolved_revision
        if self.resolved_revision_type is not None:
            vcs_info["resolved_revision_type"] = self.resolved_revision_type

        return vcs_info


@dataclass
class _BaseData(abc.ABC):
    """Base direct URL data.

    Args:
        url: The direct URL.
    """

    url: str

    @abc.abstractmethod
    def to_dict(self) -> t.Mapping[str, t.Any]:
        """Convert the data to a dictionary."""

    def to_json(self) -> str:
        """Convert the data to a JSON string.

        Returns:
            The data as a JSON string.
        """
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class VCSData(_BaseData):
    """VCS direct URL data.

    Args:
        url: The VCS URL.
        vcs_info: VCS information.
    """

    vcs_info: VCSInfo

    def to_dict(self) -> VCSDict:
        """Convert the VCS data to a dictionary.

        Returns:
            The VCS data as a dictionary.
        """
        return {"url": self.url, "vcs_info": self.vcs_info.to_dict()}


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

        .. code-block:: pycon

            >>> archive_info = ArchiveInfo(
            ...     hashes={
            ...         "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
            ...         "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
            ...     },
            ... )
            >>> archive_info.has_valid_algorithms()
            True
        """  # noqa: E501
        return set(self.all_hashes).intersection(hashlib.algorithms_guaranteed) != set()

    @property
    def all_hashes(self: Self) -> dict[str, str]:
        """All archive hashes.

        Merges the ``hashes`` attribute with the legacy ``hash`` attribute, prioritizing the former.

        Returns:
            All archive hashes.

        .. code-block:: pycon

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

    def to_dict(self) -> ArchiveInfoDict:
        """Convert the archive data to a dictionary.

        Returns:
            The archive data as a dictionary.

        .. code-block:: pycon

            >>> archive_info = ArchiveInfo(
            ...     hashes={
            ...         "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
            ...         "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
            ...     },
            ... )
            >>> archive_info.to_dict()
            {'hashes': {'sha256': '1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9', 'md5': 'c4e0f0a1e0a5e708c8e3e3c4cbe2e85f'}}
        """  # noqa: E501
        archive_info: ArchiveInfoDict = {}
        if self.hashes is not None:
            archive_info["hashes"] = self.hashes
        if self.hash is not None:
            archive_info["hash"] = f"{self.hash.algorithm}={self.hash.value}"
        return archive_info


@dataclass
class ArchiveData(_BaseData):
    """Archive direct URL data.

    Args:
        url: The archive URL.
        archive_info: Archive information.
    """

    archive_info: ArchiveInfo

    def to_dict(self) -> ArchiveDict:
        """Convert the archive data to a dictionary.

        Returns:
            The archive data as a dictionary.
        """
        return {"url": self.url, "archive_info": self.archive_info.to_dict()}


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

        .. code-block:: pycon

            >>> dir_info = DirInfo(editable=True)
            >>> dir_info.is_editable()
            True

        .. code-block:: pycon

            >>> dir_info = DirInfo(editable=False)
            >>> dir_info.is_editable()
            False

        .. code-block:: pycon

            >>> dir_info = DirInfo(editable=None)
            >>> dir_info.is_editable()
            False
        """
        return self.editable is True

    def to_dict(self) -> DirectoryInfoDict:
        """Convert the directory data to a dictionary.

        Returns:
            The directory data as a dictionary.

        .. code-block:: pycon

                >>> dir_info = DirInfo(editable=True)
                >>> dir_info.to_dict()
                {'editable': True}
        """
        dir_info: DirectoryInfoDict = {}
        if self.editable is not None:
            dir_info["editable"] = self.editable

        return dir_info


@dataclass
class DirData(_BaseData):
    """Local directory direct URL data.

    Args:
        url: The local directory URL.
        dir_info: Local directory information.
    """

    dir_info: DirInfo

    def to_dict(self) -> DirectoryDict:
        """Convert the directory data to a dictionary.

        Returns:
            The directory data as a dictionary.
        """
        return {"url": self.url, "dir_info": self.dir_info.to_dict()}


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
    return data.to_dict()


@to_dict.register(ArchiveData)
def _(data: ArchiveData) -> ArchiveDict:
    return data.to_dict()


@to_dict.register(DirData)
def _(data: DirData) -> DirectoryDict:
    return data.to_dict()


def parse(data: dict) -> VCSData | ArchiveData | DirData | None:
    """Parse the direct URL data.

    Args:
        data: The direct URL data.

    Returns:
        The parsed direct URL data.

    .. code-block:: pycon

        >>> parse(
        ...     {
        ...         "url": "https://github.com/pypa/packaging",
        ...         "vcs_info": {
        ...             "vcs": "git",
        ...             "requested_revision": "main",
        ...             "commit_id": "4f42225e91a0be634625c09e84dd29ea82b85e27"
        ...         }
        ...     }
        ... )
        VCSData(url='https://github.com/pypa/packaging', vcs_info=VCSInfo(vcs='git', commit_id='4f42225e91a0be634625c09e84dd29ea82b85e27', requested_revision='main', resolved_revision=None, resolved_revision_type=None))
    """  # noqa: E501
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

    >>> import importlib.metadata
    >>> dist = importlib.metadata.distribution("pep610")
    >>> read_from_distribution(dist)  # doctest: +SKIP
    DirData(url='file:///home/user/pep610', dir_info=DirInfo(editable=False))
    """
    if contents := dist.read_text("direct_url.json"):
        return parse(json.loads(contents))

    return None


def is_editable(distribution_name: str) -> bool:
    """Wrapper around :func:`read_from_distribution` to check if a distribution is editable.

    Args:
        distribution_name: The distribution name.

    Returns:
        Whether the distribution is editable.

    Raises:
        importlib_metadata.PackageNotFoundError: If the distribution is not found.

    >>> is_editable("pep610")  # doctest: +SKIP
    False
    """  # noqa: DAR402, RUF100
    dist = distribution(distribution_name)
    data = read_from_distribution(dist)
    return isinstance(data, DirData) and data.dir_info.is_editable()


def write_to_distribution(dist: PathDistribution, data: dict | _BaseData) -> int:
    """Write the direct URL data to a distribution.

    Args:
        dist: The distribution.
        data: The direct URL data.

    Returns:
        The number of bytes written.
    """
    to_write = json.dumps(data, sort_keys=True) if isinstance(data, dict) else data.to_json()
    return dist._path.joinpath(DIRECT_URL_METADATA_NAME).write_text(to_write)  # noqa: SLF001
