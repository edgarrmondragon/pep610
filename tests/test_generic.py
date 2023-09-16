from importlib.metadata import PathDistribution

import pytest
from hypothesis import given
from hypothesis_jsonschema import from_schema

from pep610 import read_from_distribution, write_to_distribution


@given(
    from_schema(
        {
            "allOf": [
                {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                    },
                    "required": ["url"],
                },
                {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {
                                "dir_info": {
                                    "type": "object",
                                    "properties": {"editable": {"type": "boolean"}},
                                },
                            },
                            "required": ["dir_info"],
                        },
                        {
                            "type": "object",
                            "properties": {
                                "vcs_info": {
                                    "type": "object",
                                    "properties": {
                                        "vcs": {
                                            "type": "string",
                                            "enum": ["git", "hg", "bzr", "svn"],
                                        },
                                        "requested_revision": {"type": "string"},
                                        "commit_id": {"type": "string"},
                                        "resolved_revision": {"type": "string"},
                                        "resolved_revision_type": {"type": "string"},
                                    },
                                    "required": ["vcs", "commit_id"],
                                },
                            },
                            "required": ["vcs_info"],
                        },
                        {
                            "type": "object",
                            "properties": {
                                "archive_info": {
                                    "type": "object",
                                    "properties": {
                                        "hash": {
                                            "type": "string",
                                            "pattern": r"^[a-f0-9]+=[a-f0-9]+$",
                                        },
                                    },
                                },
                            },
                            "required": ["archive_info"],
                        },
                    ],
                },
            ],
        },
    ),
)
def test_generic(tmp_path_factory: pytest.TempPathFactory, value: dict):
    """Test parsing a local directory."""
    dist_path = tmp_path_factory.mktemp("pep610")
    dist = PathDistribution(dist_path)
    write_to_distribution(dist, value)
    assert read_from_distribution(dist) is not None
