"""Sphinx configuration."""

from __future__ import annotations

import pep610

# Add any Sphinx extension module names here, as strings.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.extlinks",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "myst_parser",
    "sphinx_design",
]

# General information about the project.
project = "pep610"
author = "Edgar Ramírez-Mondragón"
version = pep610.__version__
release = pep610.__version__
project_copyright = f"2023, {author}"

# -- General configuration ----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
nitpicky = True
nitpick_ignore = [
    ("py:class", "pep610.HashData"),
]

# -- Options for HTML output --------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.

html_theme = "furo"
html_title = "PEP 610 - Direct URL Parser for Python"
html_theme_options = {
    "navigation_with_keys": True,
    "source_repository": "https://github.com/edgarrmondragon/citric/",
    "source_branch": "main",
    "source_directory": "docs/",
}

# -- Options for autodoc ----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#configuration

autodoc_member_order = "bysource"
autodoc_preserve_defaults = True

# Automatically extract typehints when specified and place them in
# descriptions of the relevant function/method.
autodoc_typehints = "description"

# Only document types for parameters or return values that are already documented by the
# docstring.
autodoc_typehints_description_target = "documented"

# -- Options for extlinks -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/extlinks.html

extlinks_detect_hardcoded_links = True
extlinks = {
    "spec": (
        "https://packaging.python.org/en/latest/specifications/direct-url-data-structure/#%s",
        "specification for %s URLs",
    ),
}

# -- Options for intersphinx ----------------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html#configuration
intersphinx_mapping = {
    "metadata": ("https://importlib-metadata.readthedocs.io/en/latest", None),
    "packaging": ("https://packaging.python.org/en/latest", None),
    "python": ("https://docs.python.org/3/", None),
}

# -- Options for Myst Parser -------------------------------------------------------
# https://myst-parser.readthedocs.io/en/latest/configuration.html
myst_enable_extensions = ["colon_fence"]
