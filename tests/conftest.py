from __future__ import annotations

import json
import os
import typing as t

import pytest

PIP_INSTALL_REPORT = """\
{
  "version": "1",
  "pip_version": "22.2",
  "install": [
    {
      "download_info": {
        "url": "https://files.pythonhosted.org/packages/a4/0c/fbaa7319dcb5eecd3484686eb5a5c5702a6445adb566f01aee6de3369bc4/pydantic-1.9.1-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "archive_info": {
          "hashes": {
            "sha256": "18f3e912f9ad1bdec27fb06b8198a2ccc32f201e24174cec1b3424dda605a310"
          }
        }
      },
      "is_direct": false,
      "is_yanked": false,
      "requested": true,
      "metadata": {
        "name": "pydantic",
        "version": "1.9.1",
        "requires_dist": [
          "typing-extensions (>=3.7.4.3)",
          "dataclasses (>=0.6) ; python_version < \\"3.7\\"",
          "python-dotenv (>=0.10.4) ; extra == 'dotenv'",
          "email-validator (>=1.0.3) ; extra == 'email'"
        ],
        "requires_python": ">=3.6.1",
        "provides_extra": [
          "dotenv",
          "email"
        ]
      }
    },
    {
      "download_info": {
        "url": "https://github.com/pypa/packaging",
        "vcs_info": {
          "vcs": "git",
          "requested_revision": "main",
          "commit_id": "4f42225e91a0be634625c09e84dd29ea82b85e27"
        }
      },
      "is_direct": true,
      "is_yanked": false,
      "requested": true,
      "metadata": {
        "name": "packaging",
        "version": "21.4.dev0",
        "requires_dist": [
          "pyparsing (!=3.0.5,>=2.0.2)"
        ],
        "requires_python": ">=3.7"
      }
    },
    {
      "download_info": {
        "url": "https://files.pythonhosted.org/packages/6c/10/a7d0fa5baea8fe7b50f448ab742f26f52b80bfca85ac2be9d35cdd9a3246/pyparsing-3.0.9-py3-none-any.whl",
        "archive_info": {
          "hashes": {
            "sha256": "5026bae9a10eeaefb61dab2f09052b9f4307d44aee4eda64b309723d8d206bbc"
          }
        }
      },
      "is_direct": false,
      "requested": false,
      "metadata": {
        "name": "pyparsing",
        "version": "3.0.9",
        "requires_dist": [
          "railroad-diagrams ; extra == \\"diagrams\\"",
          "jinja2 ; extra == \\"diagrams\\""
        ],
        "requires_python": ">=3.6.8"
      }
    },
    {
      "download_info": {
        "url": "https://files.pythonhosted.org/packages/75/e1/932e06004039dd670c9d5e1df0cd606bf46e29a28e65d5bb28e894ea29c9/typing_extensions-4.2.0-py3-none-any.whl",
        "archive_info": {
          "hashes": {
            "sha256": "6657594ee297170d19f67d55c05852a874e7eb634f4f753dbd667855e07c1708"
          }
        }
      },
      "is_direct": false,
      "requested": false,
      "metadata": {
        "name": "typing_extensions",
        "version": "4.2.0",
        "requires_python": ">=3.7"
      }
    }
  ],
  "environment": {
    "implementation_name": "cpython",
    "implementation_version": "3.10.5",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_release": "5.13-generic",
    "platform_system": "Linux",
    "platform_version": "...",
    "python_full_version": "3.10.5",
    "platform_python_implementation": "CPython",
    "python_version": "3.10",
    "sys_platform": "linux"
  }
}
"""


def pytest_report_header() -> list[str]:
    """Return a list of strings to be displayed in the header of the report."""
    return [
        f"{key}: {value}"
        for key, value in os.environ.items()
        if key.startswith(("COVERAGE_", "PYO3_"))
    ]


@pytest.fixture
def pip_install_report() -> dict[str, t.Any]:
    """Return the parsed JSON report of a pip install command."""
    return json.loads(PIP_INSTALL_REPORT)  # type: ignore[no-any-return]
