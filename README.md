# pep610

[![PyPI - Version](https://img.shields.io/pypi/v/pep610.svg)](https://pypi.org/project/pep610)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pep610.svg)](https://pypi.org/project/pep610)
[![codecov](https://codecov.io/gh/edgarrmondragon/pep610/graph/badge.svg?token=6W1M6P9LYI)](https://codecov.io/gh/edgarrmondragon/pep610)

[PEP 610][pep610] specifies how the Direct URL Origin of installed distributions should be recorded.

The up-to-date, [canonical specification][pep610-pypa] is maintained on the [PyPA specs page][pypa-specs].

-----

**Table of Contents**

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

```console
pip install pep610
```

## Usage

```python
from importlib import metadata

import pep610

dist = metadata.distribution('pep610')
data = pep610.read_from_distribution(dist)

match data:
    case pep610.DirData(url, dir_info):
        print(f"URL: {url}")
        print(f"Editable: {dir_info.editable}")
    case pep610.VCSData(url, vcs_info):
        print(f"URL: {url}")
        print(f"VCS: {vcs_info.vcs}")
        print(f"Commit: {vcs_info.commit_id}")
    case pep610.ArchiveData(url, archive_info):
        print(f"URL: {url}")
        print(f"Hash: {archive_info.hash}")
    case _:
        print("Unknown data")
```

## License

`pep610` is distributed under the terms of the [Apache License 2.0](LICENSE).

[pep610]: https://www.python.org/dev/peps/pep-0610/
[pep610-pypa]: https://packaging.python.org/en/latest/specifications/direct-url/#direct-url
[pypa-specs]: https://packaging.python.org/en/latest/specifications/
