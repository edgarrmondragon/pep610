"""Test the PEP 610 parser."""

import json
from pathlib import Path

import pytest

from pep610 import (
    ArchiveData,
    ArchiveInfo,
    DirData,
    DirInfo,
    HashData,
    VCSData,
    VCSInfo,
    parse,
    to_dict,
)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": True}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(_editable=True),
            ),
            id="local_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {"editable": False}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(_editable=False),
            ),
            id="local_not_editable",
        ),
        pytest.param(
            {"url": "file:///home/user/project", "dir_info": {}},
            DirData(
                url="file:///home/user/project",
                dir_info=DirInfo(_editable=None),
            ),
            id="local_no_editable_info",
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
            id="archive_sha256",
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
            id="archive_no_hash",
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
    ],
)
def test_parse(data: dict, expected: object, tmp_path: Path):
    """Test the parse function."""
    filepath = tmp_path.joinpath("direct_url.json")
    with filepath.open("w") as f:
        json.dump(data, f)

    result = parse(filepath)
    assert result == expected

    assert to_dict(result) == data
