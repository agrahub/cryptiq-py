# Python Package Template

Production-ready Python package template with modern tooling, strict typing, and scalable project structure.

## Features

- Modern `uv`-based workflow
- `src/` package layout
- Ruff linting and formatting
- Pyright static type checking
- pytest testing setup
- GitHub Actions CI
- PEP 621 packaging
- Pre-configured pre-commit hooks
- Typed package support via `py.typed`

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
├── src/
│   └── package_name/
├── tests/
├── .gitignore
├── .pre-commit-config.yaml
├── LICENSE
├── pyproject.toml
└── README.md
```

---

## Requirements

- Python 3.13+
- `uv`

Install `uv` by following the official documentation:

- https://docs.astral.sh/uv/getting-started/installation/

---

## Quick Start

### Create virtual environment

```bash
uv venv
```

### Install dependencies

```bash
uv sync
```

### Run tests

```bash
uv run pytest
```

### Run linting

```bash
uv run ruff check .
```

### Run formatting

```bash
uv run ruff format .
```

### Run type checking

```bash
uv run pyright
```

---

## Included Tooling

### Ruff

Used for:
- linting
- formatting
- import sorting

### Pyright

Used for strict static type checking.

### pytest

Used for testing.

### pre-commit

Runs automated checks before commits.

---

## Design Principles

This template prioritizes:

- simplicity
- strict typing
- reproducibility
- scalable project structure
- modern Python standards
- minimal tooling friction

---

## License

MIT