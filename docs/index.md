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
.. autofunction:: pep610.read_from_distribution
```
