from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import distribution
from typing import TYPE_CHECKING, Any, ClassVar, Literal, NamedTuple, TypeVar

if TYPE_CHECKING:
    from importlib.metadata import Distribution, PathDistribution
    from typing import Self

    from pep610._types import (
        ArchiveInfoDict,
        DirectoryInfoDict,
        DirectUrlDict,
        VCSInfoDict,
    )

T = TypeVar("T")

DIRECT_URL_METADATA_NAME = "direct_url.json"

_INFO_KEYS: tuple[Literal["archive_info", "dir_info", "vcs_info"], ...] = (
    "archive_info",
    "dir_info",
    "vcs_info",
)


class DirectUrlValidationError(Exception):
    """Direct URL validation error."""


def _filter_none(**kwargs: T) -> dict[str, T]:
    """Make dict excluding None values.

    Returns:
        A dictionary with all the values that are not ``None``.
    """
    return {k: v for k, v in kwargs.items() if v is not None}


@dataclass
class VCSInfo:
    """VCS information.

    See the :spec:`VCS URLs specification <vcs-urls>`.

    Args:
        vcs: The VCS type.
        commit_id: The exact commit/revision number that was/is to be installed.
        requested_revision: A branch/tag/ref/commit/revision/etc (in a format
            compatible with the VCS).
        resolved_revision: The revision that ``requested_revision`` resolved to.
        resolved_revision_type: The type of the resolved revision, e.g. ``tag``.
    """

    key: ClassVar[str] = "vcs_info"

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
        """  # ruff:ignore[line-too-long]
        return _filter_none(  # type: ignore[return-value]
            vcs=self.vcs,
            commit_id=self.commit_id,
            requested_revision=self.requested_revision,
            resolved_revision=self.resolved_revision,
            resolved_revision_type=self.resolved_revision_type,
        )  # ty:ignore[invalid-return-type]


class HashData(NamedTuple):
    """(Deprecated) Archive hash data tuple."""

    #: The hash algorithm.
    algorithm: str

    #: The hash value.
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

    key: ClassVar[str] = "archive_info"

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
        """  # ruff:ignore[line-too-long]
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
        """  # ruff:ignore[line-too-long]
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
        """  # ruff:ignore[line-too-long]
        return _filter_none(  # type: ignore[return-value]
            hashes=self.hashes,
            hash=self.hash and f"{self.hash.algorithm}={self.hash.value}",  # pyrefly: ignore[implicit-bool]
        )  # ty:ignore[invalid-return-type]


@dataclass
class DirInfo:
    """Local directory information.

    See the :spec:`Local Directories specification <local-directories>`.

    Args:
        editable: Whether the distribution is installed in editable mode.
    """

    key: ClassVar[str] = "dir_info"

    editable: bool | None = None

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
        return _filter_none(editable=self.editable)  # type: ignore[return-value]  # ty:ignore[invalid-return-type]


@dataclass
class DirectUrl:
    """Direct URL data.

    Args:
        url: The direct URL.
        info: The direct URL data.
        subdirectory: The optional directory path, relative to the root of the VCS repository,
            source archive or local directory, to specify where pyproject.toml or setup.py
            is located.
    """

    url: str
    info: VCSInfo | ArchiveInfo | DirInfo
    subdirectory: str | None = None

    def to_dict(self) -> DirectUrlDict:
        """Convert the data to a dictionary.

        Returns:
            The data as a dictionary.

        .. code-block:: pycon

            >>> direct_url = DirectUrl(
            ...     url="file:///home/user/pep610",
            ...     info=DirInfo(editable=False),
            ...     subdirectory="app",
            ... )
            >>> direct_url.to_dict()
            {'url': 'file:///home/user/pep610', 'subdirectory': 'app', 'dir_info': {'editable': False}}
        """  # ruff:ignore[line-too-long]
        res = _filter_none(url=self.url, subdirectory=self.subdirectory)
        res[self.info.key] = self.info.to_dict()  # type: ignore[assignment]  # ty:ignore[invalid-assignment]
        return res  # type: ignore[return-value]  # ty:ignore[invalid-return-type]

    def to_json(self) -> str:
        """Convert the data to a JSON string.

        Returns:
            The data as a JSON string.

        .. code-block:: pycon

            >>> direct_url = DirectUrl(
            ...     url="file:///home/user/pep610",
            ...     info=DirInfo(editable=False),
            ...     subdirectory="app",
            ... )
            >>> direct_url.to_json()
            '{"dir_info": {"editable": false}, "subdirectory": "app", "url": "file:///home/user/pep610"}'
        """
        return json.dumps(self.to_dict(), sort_keys=True)


def to_dict(data: DirectUrl) -> DirectUrlDict:
    """Convert the parsed data to a dictionary.

    Args:
        data: The parsed data.

    Returns:
        The data as a dictionary.
    """
    return data.to_dict()


def parse(data: Mapping[str, Any]) -> DirectUrl:  # pyrefly: ignore[explicit-any]
    """Parse the direct URL data.

    Args:
        data: The direct URL data.

    Returns:
        The parsed direct URL data.

    Raises:
        DirectUrlValidationError: If the data is malformed: ``url`` is missing, there is not
            exactly one of ``archive_info``, ``dir_info`` or ``vcs_info``, or a required field
            is missing or invalid.

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
        DirectUrl(url='https://github.com/pypa/packaging', info=VCSInfo(vcs='git', commit_id='4f42225e91a0be634625c09e84dd29ea82b85e27', requested_revision='main', resolved_revision=None, resolved_revision_type=None), subdirectory=None)
    """  # ruff:ignore[line-too-long]
    if not isinstance(data, Mapping):
        msg = "Direct URL data must be a JSON object"  # type: ignore[unreachable]
        raise DirectUrlValidationError(msg)

    if not isinstance(url := data.get("url"), str):
        msg = "Direct URL data must contain a string 'url'"
        raise DirectUrlValidationError(msg)

    present = [key for key in _INFO_KEYS if data.get(key) is not None]
    if len(present) != 1:
        msg = (
            "Direct URL data must contain exactly one of 'archive_info', 'dir_info', "
            f"or 'vcs_info', found: {present or 'none'}"  # pyrefly: ignore[implicit-bool]
        )
        raise DirectUrlValidationError(msg)

    key = present[0]
    info = data[key]
    if not isinstance(info, Mapping):
        msg = f"'{key}' must be an object"
        raise DirectUrlValidationError(msg)

    subdirectory = data.get("subdirectory")

    if key == ArchiveInfo.key:
        hash_data = None
        if hash_value := info.get("hash"):  # pyrefly: ignore[implicit-bool]
            algorithm, sep, digest = hash_value.partition("=")  # pyrefly: ignore[unknown-attribute-access, unknown-variable-type]
            if not sep:
                msg = "'archive_info.hash' must have the form '<algorithm>=<digest>'"
                raise DirectUrlValidationError(msg)
            hash_data = HashData(algorithm, digest)  # pyrefly: ignore[unknown-argument-type]

        return DirectUrl(
            url=url,
            info=ArchiveInfo(hashes=info.get("hashes"), hash=hash_data),
            subdirectory=subdirectory,
        )

    if key == DirInfo.key:
        return DirectUrl(
            url=url,
            info=DirInfo(editable=info.get("editable")),
            subdirectory=subdirectory,
        )

    if "vcs" not in info or "commit_id" not in info:
        msg = "'vcs_info' must contain 'vcs' and 'commit_id'"
        raise DirectUrlValidationError(msg)

    return DirectUrl(
        url=url,
        info=VCSInfo(
            vcs=info["vcs"],  # pyrefly: ignore[unknown-argument-type]
            commit_id=info["commit_id"],  # pyrefly: ignore[unknown-argument-type]
            requested_revision=info.get("requested_revision"),
            resolved_revision=info.get("resolved_revision"),
            resolved_revision_type=info.get("resolved_revision_type"),
        ),
        subdirectory=subdirectory,
    )


def read_from_distribution(dist: Distribution) -> DirectUrl | None:
    """Read the package data for a given package.

    Args:
        dist(importlib.metadata.Distribution): The package distribution.

    Returns:
        The parsed PEP 610 data or ``None`` if the file is not found.

    Raises:
        DirectUrlValidationError: If the file is not valid JSON or not valid direct URL data.

    >>> import importlib.metadata
    >>> dist = importlib.metadata.distribution("pep610")
    >>> read_from_distribution(dist)  # doctest: +SKIP
    DirData(url='file:///home/user/pep610', dir_info=DirInfo(editable=False))
    """
    if (contents := dist.read_text(DIRECT_URL_METADATA_NAME)) is not None:
        try:
            data = json.loads(contents)
        except json.JSONDecodeError as exc:
            msg = f"{DIRECT_URL_METADATA_NAME} is not valid JSON"
            raise DirectUrlValidationError(msg) from exc
        return parse(data)

    return None


def is_editable(distribution_name: str) -> bool:
    """Wrapper around :func:`read_from_distribution` to check if a distribution is editable.

    Args:
        distribution_name: The distribution name.

    Returns:
        Whether the distribution is editable.

    Note:
        :class:`importlib.metadata.PackageNotFoundError` propagates if the distribution is not
        installed.

    >>> is_editable("pep610")  # doctest: +SKIP
    False
    """
    dist = distribution(distribution_name)
    data = read_from_distribution(dist)
    return data is not None and isinstance(data.info, DirInfo) and data.info.is_editable()


def write_to_distribution(dist: PathDistribution, data: DirectUrlDict | DirectUrl) -> int:
    """Write the direct URL data to a distribution.

    Args:
        dist: The distribution.
        data: The direct URL data.

    Returns:
        The number of bytes written.
    """
    to_write = json.dumps(data, sort_keys=True) if isinstance(data, Mapping) else data.to_json()
    return dist._path.joinpath(DIRECT_URL_METADATA_NAME).write_text(to_write)  # type: ignore[attr-defined,no-any-return]  # ty:ignore[unresolved-attribute]  # ruff: ignore[private-member-access]
