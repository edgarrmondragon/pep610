"""Test the PEP 610 parser."""

from __future__ import annotations

import typing as t
from importlib.metadata import Distribution

import pytest

from pep610 import (
    ArchiveData,
    ArchiveInfo,
    DirData,
    DirInfo,
    HashData,
    VCSData,
    VCSInfo,
    read_from_distribution,
    to_dict,
    write_to_distribution,
)

if t.TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": True}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(editable=True),
            ),
            id="local_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": False}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(editable=False),
            ),
            id="local_not_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(editable=None),
            ),
            id="local_no_editable_info",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip/archive/1.3.1.zip",
                "archive_info": {
                    "hashes": {
                        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
                        "sha256": "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",  # noqa: E501
                    }
                },
            },
            ArchiveData(
                url="https://github.com/pypa/pip/archive/1.3.1.zip",
                archive_info=ArchiveInfo(
                    hashes={
                        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
                        "sha256": "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",  # noqa: E501
                    },
                ),
            ),
            id="archive_hashes",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip/archive/1.3.1.zip",
                "archive_info": {
                    "hash": "sha256=2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",  # noqa: E501
                },
            },
            ArchiveData(
                url="https://github.com/pypa/pip/archive/1.3.1.zip",
                archive_info=ArchiveInfo(
                    hash=HashData(
                        "sha256",
                        "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",
                    ),
                ),
            ),
            id="archive_sha256_legacy",
        ),
        pytest.param(
            {
                "url": "file://path/to/my.whl",
                "archive_info": {},
            },
            ArchiveData(
                url="file://path/to/my.whl",
                archive_info=ArchiveInfo(hash=None),
            ),
            id="archive_no_hashes",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "1.3.1",
                    "resolved_revision_type": "tag",
                    "commit_id": "7921be1537eac1e97bc40179a57f0349c2aee67d",
                },
            },
            VCSData(
                url="https://github.com/pypa/pip.git",
                vcs_info=VCSInfo(
                    vcs="git",
                    requested_revision="1.3.1",
                    resolved_revision_type="tag",
                    commit_id="7921be1537eac1e97bc40179a57f0349c2aee67d",
                ),
            ),
            id="vcs_git",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip.git",
                "vcs_info": {
                    "vcs": "git",
                    "resolved_revision_type": "tag",
                    "commit_id": "7921be1537eac1e97bc40179a57f0349c2aee67d",
                },
            },
            VCSData(
                url="https://github.com/pypa/pip.git",
                vcs_info=VCSInfo(
                    vcs="git",
                    requested_revision=None,
                    resolved_revision_type="tag",
                    commit_id="7921be1537eac1e97bc40179a57f0349c2aee67d",
                ),
            ),
            id="vcs_git_no_requested_revision",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "1.3.1",
                    "resolved_revision": "1.3.1",
                    "resolved_revision_type": "tag",
                    "commit_id": "7921be1537eac1e97bc40179a57f0349c2aee67d",
                },
            },
            VCSData(
                url="https://github.com/pypa/pip.git",
                vcs_info=VCSInfo(
                    vcs="git",
                    requested_revision="1.3.1",
                    resolved_revision="1.3.1",
                    resolved_revision_type="tag",
                    commit_id="7921be1537eac1e97bc40179a57f0349c2aee67d",
                ),
            ),
            id="vcs_git_resolved_revision",
        ),
        pytest.param(
            {
                "url": "https://github.com/pypa/pip.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "1.3.1",
                    "resolved_revision": "1.3.1",
                    "commit_id": "7921be1537eac1e97bc40179a57f0349c2aee67d",
                },
            },
            VCSData(
                url="https://github.com/pypa/pip.git",
                vcs_info=VCSInfo(
                    vcs="git",
                    requested_revision="1.3.1",
                    resolved_revision="1.3.1",
                    resolved_revision_type=None,
                    commit_id="7921be1537eac1e97bc40179a57f0349c2aee67d",
                ),
            ),
            id="vcs_no_resolved_revision",
        ),
    ],
)
def test_parse(data: dict, expected: object, tmp_path: Path):
    """Test the parse function."""
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)

    result = read_from_distribution(dist)
    assert result == expected

    assert to_dict(result) == data


def test_unknown_data_type():
    """Test serialization from unknown data fails."""
    data = object()
    with pytest.raises(NotImplementedError, match="Cannot serialize unknown"):
        to_dict(data)


def test_local_directory(tmp_path: Path):
    """Test that a local directory is read back as a local directory."""
    data = {
        "url": "file:///home/user/project",
        "dir_info": {"editable": True},
    }
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)

    result = read_from_distribution(dist)
    assert isinstance(result, DirData)
    assert result.url == "file:///home/user/project"
    assert result.dir_info.is_editable()
    assert to_dict(result) == data

    result.dir_info.editable = False
    assert to_dict(result) == {
        "url": "file:///home/user/project",
        "dir_info": {"editable": False},
    }

    result.dir_info.editable = None
    assert to_dict(result) == {
        "url": "file:///home/user/project",
        "dir_info": {},
    }


def test_archive_hashes_merged(tmp_path: Path):
    """Test that archive hashes are merged."""
    data = {
        "url": "file://path/to/my.whl",
        "archive_info": {
            "hash": "sha256=2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",
            "hashes": {
                "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
                "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
            },
        },
    }
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)

    result = read_from_distribution(dist)
    assert isinstance(result, ArchiveData)
    assert result.url == "file://path/to/my.whl"
    assert result.archive_info.hash == HashData(
        "sha256",
        "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",
    )
    assert result.archive_info.hashes == {
        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
    }
    assert result.archive_info.all_hashes == {
        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
    }


def test_archive_no_hashes(tmp_path: Path):
    """Test an archive with no hashes."""
    data = {
        "url": "file://path/to/my.whl",
        "archive_info": {},
    }
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)

    result = read_from_distribution(dist)
    assert isinstance(result, ArchiveData)
    assert result.url == "file://path/to/my.whl"
    assert result.archive_info.hash is None
    assert result.archive_info.hashes is None
    assert result.archive_info.all_hashes == {}


def test_archive_no_valid_algorithms(tmp_path: Path):
    """Test an archive without any of the required algorithms."""
    data = {
        "url": "file://path/to/my.whl",
        "archive_info": {
            "hashes": {
                "notavalidalgo": "1234",
            },
        },
    }
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)

    result = read_from_distribution(dist)
    assert isinstance(result, ArchiveData)
    assert result.url == "file://path/to/my.whl"
    assert result.archive_info.hash is None
    assert result.archive_info.hashes == {"notavalidalgo": "1234"}
    assert result.archive_info.all_hashes == {"notavalidalgo": "1234"}
    assert not result.archive_info.has_valid_algorithms()


def test_unknown_url_type(tmp_path: Path):
    """Test that an unknown URL type is read back as None."""
    data = {
        "url": "unknown:///home/user/project",
        "unknown_info": {},
    }
    dist = Distribution.at(tmp_path)
    write_to_distribution(dist, data)
    assert read_from_distribution(dist) is None


def test_no_file(tmp_path: Path):
    """Test that a missing file is read back as None."""
    dist = Distribution.at(tmp_path)
    assert read_from_distribution(dist) is None
