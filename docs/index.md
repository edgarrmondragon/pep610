# PEP 610 Parser

*A parser for {external:doc}`PEP 610 direct URL metadata <specifications/direct-url>`.*

Release **v{sub-ref}`version`**.

::::{tab-set}

:::{tab-item} Python 3.10+

```python
from importlib import metadata

import pep610

dist = metadata.distribution("pep610")

match data := pep610.read_from_distribution(dist):
    case pep610.DirData(url, pep610.DirInfo(editable=True)):
        print("Editable installation, a.k.a. in development mode")
    case _:
        print("Not an editable installation")
```

:::

:::{tab-item} Python 3.8+
```python
from importlib import metadata

import pep610

dist = metadata.distribution("pep610")

if (
    (data := pep610.read_from_distribution(dist))
    and isinstance(data, pep610.DirData)
    and data.dir_info.is_editable()
):
    print("Editable installation, a.k.a. in development mode")
else:
    print("Not an editable installation")
```
:::
::::

It can also be used to parse the direct URL download info in pip's {external:doc}`reference/installation-report`:

```python
import json
import subprocess

import pep610

report = json.loads(
    subprocess.run(
        [
            "pip",
            "install",
            "--quiet",
            "--report",
            "-",
            "--dry-run",
            "git+https://github.com/pypa/packaging@main",
        ],
        capture_output=True,
        text=True,
    ).stdout
)

for package in report["install"]:
    if package["is_direct"]:
        data = pep610.parse(package["download_info"])
        print(data)
```

## Supported formats

```{eval-rst}
.. autoclass:: pep610.ArchiveData
    :members:
```

```{eval-rst}
.. autoclass:: pep610.DirData
    :members:
```

```{eval-rst}
.. autoclass:: pep610.VCSData
    :members:
```

## Other classes

```{eval-rst}
.. autoclass:: pep610.ArchiveInfo
    :members:
```

```{eval-rst}
.. autoclass:: pep610.DirInfo
    :members:
```

```{eval-rst}
.. autoclass:: pep610.VCSInfo
    :members:
```

## Functions

```{eval-rst}
.. autofunction:: pep610.parse
```

```{eval-rst}
.. autofunction:: pep610.read_from_distribution
```

```{eval-rst}
.. autofunction:: pep610.is_editable
```

## Exceptions

```{eval-rst}
.. autoclass:: pep610.DirectUrlValidationError
```

## Types

```{eval-rst}
.. autoclass:: pep610._types.ArchiveInfoDict
    :members: hashes, hash
```

```{eval-rst}
.. autoclass:: pep610._types.ArchiveDict
    :members: url, archive_info
```

```{eval-rst}
.. autoclass:: pep610._types.DirectoryInfoDict
    :members: editable
```

```{eval-rst}
.. autoclass:: pep610._types.DirectoryDict
    :members: url, dir_info
```

```{eval-rst}
.. autoclass:: pep610._types.VCSInfoDict
    :members: vcs, commit_id, requested_revision, resolved_revision, resolved_revision_type
```

```{eval-rst}
.. autoclass:: pep610._types.VCSDict
    :members: url ,vcs_info
```
