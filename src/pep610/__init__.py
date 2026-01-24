"""PEP 610 parser."""

from __future__ import annotations

from importlib.metadata import version

from pep610._pep610 import (
    ArchiveInfo,
    DirectUrl,
    DirectUrlValidationError,
    DirInfo,
    HashData,
    VCSInfo,
    is_editable,
    parse,
    read_from_distribution,
    to_dict,
    write_to_distribution,
)

__all__ = [
    "ArchiveInfo",
    "DirInfo",
    "DirectUrl",
    "DirectUrlValidationError",
    "HashData",
    "VCSInfo",
    "__version__",
    "is_editable",
    "parse",
    "read_from_distribution",
    "to_dict",
    "write_to_distribution",
]

__version__ = version("pep610")
