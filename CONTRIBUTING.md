# Contributing to Surfactant

Thank you for considering contributing to our project! We appreciate your help.

## Reporting Issues

1. If you find a bug or have a feature request, please [open a new issue](https://github.com/LLNL/Surfactant/issues) and provide detailed information about the problem.
2. If you find security issues or vulnerabilities, please [report here](https://github.com/LLNL/Surfactant/security)

## Making Contributions

We welcome contributions from the community. To contribute to this project, follow these steps:

1. Fork the repository on GitHub.
2. Clone your forked repository to your local machine.

All contributions to Surfactant are made under the MIT license (MIT).

### For Developers:

1. Create a virtual environment with python >= 3.8 [Optional, but recommended]

```bash
python -m venv venv
source venv/bin/activate
```

2. Clone sbom-surfactant

```bash
git clone git@github.com:LLNL/Surfactant.git
```

3. Create an editable surfactant install (changes to code will take effect immediately):

```bash
pip install -e .
```

To install optional dependencies required for running pytest and pre-commit:

```bash
pip install -e ".[test,dev]"
```

`pip install` with the `-e` or `--editable` option can also be used to install Surfactant plugins for development.

## Adding dependencies

A special note for adding dependencies is that we aim to make the core of Surfactant pure Python with no requirements for compiled extensions or tools. This helps to maximize portability to new systems. For tools that rely on platform specific binaries, it may be better to contribute as an optional plugin instead.

The [PyPI Dependency Analyzer](https://surfactant.readthedocs.io/en/latest/pypi_dependency_analyzer.html) can be used to verify a potential new dependency doesn’t introduce problematic indirect dependencies.

## Code of Conduct

All participants in the Surfactant community are expected to follow our [Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct.html).
