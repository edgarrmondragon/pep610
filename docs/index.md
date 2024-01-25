# PEP 610 Parser and Builder

*A parser and builder for {external:doc}`PEP 610 direct URL metadata <specifications/direct-url>`.*

Release **v{sub-ref}`version`**.

::::{tab-set}

:::{tab-item} Python 3.10+

```python
from importlib import metadata

import pep610

dist = metadata.distribution("pep610")
data = pep610.read_from_distribution(dist)

match data:
    case pep610.DirData(url, pep610.DirInfo(editable=True)):
        print("Editable install")
    case _:
        print("Not editable install")
```

:::

:::{tab-item} Python 3.8+
```python
from importlib import metadata

import pep610

dist = metadata.distribution("pep610")
data = pep610.read_from_distribution(dist)

if isinstance(data, pep610.DirData) and data.dir_info.is_editable():
    print("Editable install")
else:
    print("Not editable install")
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
