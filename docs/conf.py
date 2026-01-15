import os
import shutil
import sys

import requests

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Surfactant"
# pylint: disable-next=redefined-builtin
copyright = "2023, Lawrence Livermore National Security"
author = "Ryan Mast, Kendall Harter, Micaela Gallegos, Shayna Kapadia, Apoorv Pochiraju, Alexander Armstrong, Levi Lloyd"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.githubpages",
    "sphinx_copybutton",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "images.toml"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_theme_options = {
    "source_repository": "https://github.com/llnl/Surfactant",
    "source_branch": "main",
    "source_directory": "docs/",
}

# -- Extension configuration -------------------------------------------------

# Napoleon settings for NumPy and Google style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
html_logo = "./logos/surfactant-logo-light.png"
html_favicon = html_logo
html_static_path = ["_static"]

# -- Extension - CopyButton - Configuration ----------------------------------

# https://sphinx-copybutton.readthedocs.io/en/latest/use.html#using-regexp-prompt-identifiers
copybutton_prompt_text = r">>> |\.\.\. |\$ |\$\w|In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
# https://sphinx-copybutton.readthedocs.io/en/latest/use.html#honor-here-document-syntax-when-copying-multiline-snippets
copybutton_here_doc_delimiter = "EOT"


# -- Fetch image references --------------------------------------------------
# Download all of the image files referenced in images.toml
def download_images_from_toml(toml_file, image_dir):
    with open(toml_file, "rb") as f:
        data = tomllib.load(f)

    if not os.path.exists(image_dir):
        os.makedirs(image_dir)

    for file_name, url in data.get("images", {}).items():
        if file_name and url:
            response = requests.get(url)
            if response.status_code == 200:
                with open(os.path.join(image_dir, file_name), "wb") as img_file:
                    img_file.write(response.content)
            else:
                print(f"Failed to download {url}")


# Path to the TOML file
toml_file_path = os.path.join(os.path.dirname(__file__), "images.toml")
# Directory to save the images
image_directory = os.path.join(os.path.dirname(__file__), "img")

# Download images
download_images_from_toml(toml_file_path, image_directory)

# -------------------------------------------------------------------
# Make database_sources.toml available as a static file at the site root
# https://surfactant.readthedocs.io/en/latest/database_sources.toml
# Make CyTRICS schema available as a static file in a subfolder
# -------------------------------------------------------------------
html_extra_path = ["database_sources.toml", "_static_html"]


# -------------------------------------------------------------------
# Make CyTRICS schema available as a static file under cytrics_schema/
# -------------------------------------------------------------------
def _copy_cytrics_schema(app, exception):
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "cytrics_schema", "schema.json"))
    if not os.path.exists(src):
        # Add a warning to the RTD logs instead of failing the build
        print(f"cytrics_schema.json not found at {src}")
        return
    dst_dir = os.path.join(app.outdir, "cytrics_schema")
    os.makedirs(dst_dir, exist_ok=True)
    shutil.copy(src, os.path.join(dst_dir, "schema.json"))


# Build process needs some customization to preserve the cytrics_schema subfolder
def setup(app):
    app.connect("build-finished", _copy_cytrics_schema)
