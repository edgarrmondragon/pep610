"""Test the PEP 610 parser."""

from __future__ import annotations

import typing as t
from importlib.metadata import Distribution

import pytest

import pep610

if t.TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": True}},
            pep610.DirectUrl(
                url="file:///home/user/project",
                info=pep610.DirInfo(editable=True),
            ),
            id="local_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": False}},
            pep610.DirectUrl(
                url="file:///home/user/project",
                info=pep610.DirInfo(editable=False),
            ),
            id="local_not_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {}},
            pep610.DirectUrl(
                url="file:///home/user/project",
                info=pep610.DirInfo(editable=None),
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip/archive/1.3.1.zip",
                info=pep610.ArchiveInfo(
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip/archive/1.3.1.zip",
                info=pep610.ArchiveInfo(
                    hash=pep610.HashData(
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
            pep610.DirectUrl(
                url="file://path/to/my.whl",
                info=pep610.ArchiveInfo(hash=None),
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip.git",
                info=pep610.VCSInfo(
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip.git",
                info=pep610.VCSInfo(
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip.git",
                info=pep610.VCSInfo(
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
            pep610.DirectUrl(
                url="https://github.com/pypa/pip.git",
                info=pep610.VCSInfo(
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
def test_parse(data: dict[str, t.Any], expected: object, tmp_path: Path) -> None:
    """Test the parse function."""
    dist = Distribution.at(tmp_path)
    pep610.write_to_distribution(dist, data)

    result = pep610.read_from_distribution(dist)
    assert result == expected

    assert pep610.to_dict(result) == data


def test_to_json() -> None:
    """Test the to_json method."""
    data = pep610.DirectUrl(
        url="file:///home/user/project",
        info=pep610.DirInfo(editable=True),
    )

    assert data.to_json() == '{"dir_info": {"editable": true}, "url": "file:///home/user/project"}'


def test_local_directory(tmp_path: Path) -> None:
    """Test that a local directory is read back as a local directory."""
    data = {
        "url": "file:///home/user/project",
        "dir_info": {"editable": True},
    }
    dist = Distribution.at(tmp_path)
    pep610.write_to_distribution(dist, data)

    result = pep610.read_from_distribution(dist)
    assert isinstance(result, pep610.DirectUrl)
    assert result.url == "file:///home/user/project"
    assert isinstance(result.info, pep610.DirInfo)
    assert result.info.is_editable()
    assert pep610.to_dict(result) == data

    result.info.editable = False
    assert pep610.to_dict(result) == {
        "url": "file:///home/user/project",
        "dir_info": {"editable": False},
    }

    result.info.editable = None
    assert pep610.to_dict(result) == {
        "url": "file:///home/user/project",
        "dir_info": {},
    }


def test_archive_hashes_merged(tmp_path: Path) -> None:
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
    pep610.write_to_distribution(dist, data)

    result = pep610.read_from_distribution(dist)
    assert isinstance(result, pep610.DirectUrl)
    assert result.url == "file://path/to/my.whl"
    assert isinstance(result.info, pep610.ArchiveInfo)
    assert result.info.hash == pep610.HashData(
        "sha256",
        "2dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db8",
    )
    assert result.info.hashes == {
        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
    }
    assert result.info.all_hashes == {
        "md5": "c4e0f0a1e0a5e708c8e3e3c4cbe2e85f",
        "sha256": "1dc6b5a470a1bde68946f263f1af1515a2574a150a30d6ce02c6ff742fcc0db9",
    }


def test_archive_no_hashes(tmp_path: Path) -> None:
    """Test an archive with no hashes."""
    data = {
        "url": "file://path/to/my.whl",
        "archive_info": {},
    }
    dist = Distribution.at(tmp_path)
    pep610.write_to_distribution(dist, data)

    result = pep610.read_from_distribution(dist)
    assert isinstance(result, pep610.DirectUrl)
    assert result.url == "file://path/to/my.whl"
    assert isinstance(result.info, pep610.ArchiveInfo)
    assert result.info.hash is None
    assert result.info.hashes is None
    assert result.info.all_hashes == {}


def test_archive_no_valid_algorithms(tmp_path: Path) -> None:
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
    pep610.write_to_distribution(dist, data)

    result = pep610.read_from_distribution(dist)
    assert isinstance(result, pep610.DirectUrl)
    assert result.url == "file://path/to/my.whl"
    assert isinstance(result.info, pep610.ArchiveInfo)
    assert result.info.hash is None
    assert result.info.hashes == {"notavalidalgo": "1234"}
    assert result.info.all_hashes == {"notavalidalgo": "1234"}
    assert not result.info.has_valid_algorithms()


def test_unknown_url_type(tmp_path: Path) -> None:
    """Test that an unknown URL type is read back as None."""
    data = {
        "url": "unknown:///home/user/project",
        "unknown_info": {},
    }
    dist = Distribution.at(tmp_path)
    pep610.write_to_distribution(dist, data)

    with pytest.raises(pep610.DirectUrlValidationError, match="does not contain"):
        pep610.read_from_distribution(dist)


def test_no_file(tmp_path: Path) -> None:
    """Test that a missing file is read back as None."""
    dist = Distribution.at(tmp_path)
    assert pep610.read_from_distribution(dist) is None


def _get_direct_url_packages(report: dict[str, t.Any]) -> dict[str, pep610.DirectUrl]:
    """Get direct URL packages from a pip install report."""
    return {
        package["metadata"]["name"]: pep610.parse(package["download_info"])
        for package in report["install"]
        if package["is_direct"]
    }


def test_parse_pip_install_report(pip_install_report: dict[str, t.Any]) -> None:
    """Test parsing a pip install report."""
    packages = _get_direct_url_packages(pip_install_report)

    assert packages == {
        "packaging": pep610.DirectUrl(
            url="https://github.com/pypa/packaging",
            info=pep610.VCSInfo(
                vcs="git",
                requested_revision="main",
                commit_id="4f42225e91a0be634625c09e84dd29ea82b85e27",
            ),
        ),
    }


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            {
                "url": "file:///home/user/project",
                "dir_info": {"editable": True},
            },
            True,
            id="editable",
        ),
        pytest.param(
            {
                "url": "file:///home/user/project",
                "dir_info": {"editable": False},
            },
            False,
            id="not_editable",
        ),
        pytest.param(
            {
                "url": "file:///home/user/project",
                "dir_info": {},
            },
            False,
            id="no_editable_info",
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
            False,
            id="vcs_git",
        ),
    ],
)
def test_is_editable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: dict[str, t.Any],
    expected: bool,  # noqa: FBT001
) -> None:
    """Test the is_editable function."""
    dist = Distribution.at(tmp_path)
    pep610.write_to_distribution(dist, data)

    monkeypatch.setattr("pep610.distribution", lambda _: dist)
    assert pep610.is_editable("my_package") is expected
