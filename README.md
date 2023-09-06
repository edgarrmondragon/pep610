# pep610

[![PyPI - Version](https://img.shields.io/pypi/v/pep610.svg)](https://pypi.org/project/pep610)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pep610.svg)](https://pypi.org/project/pep610)

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
