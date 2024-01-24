import json
from importlib.metadata import Distribution

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis_jsonschema import from_schema

from pep610 import SCHEMA_FILE, read_from_distribution, write_to_distribution

SCHEMA = json.loads(SCHEMA_FILE.read_text())


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(from_schema(SCHEMA))
def test_generic(tmp_path_factory: pytest.TempPathFactory, value: dict):
    """Test parsing a local directory."""
    dist_path = tmp_path_factory.mktemp("pep610")
    dist = Distribution.at(dist_path)
    write_to_distribution(dist, value)
    assert read_from_distribution(dist) is not None
