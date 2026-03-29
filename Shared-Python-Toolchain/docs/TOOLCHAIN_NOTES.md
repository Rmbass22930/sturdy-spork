# Shared Python Toolchain Notes

Last verified: 2026-03-29

## Release history
- `shared-toolchain-stable-2026-03-29`
  Merged baseline after the shared toolchain rename, history cleanup, Security Gateway typing/cache cleanup, proxy auth hardening, websocket origin hardening, and regression test expansion.

## Runtimes
- Python `3.13`
- Python `3.14`

## Core packaging and env tools
- `pip`
- `uv`
- `build`
- `wheel`
- `virtualenv`
- `pip-tools` (`pip-compile`, `pip-sync`)

## Test and coverage
- `pytest`
- `pytest-asyncio`
- `pytest-cov`
- `pytest-xdist`
- `coverage`

## Lint, typing, and analysis
- `ruff`
- `mypy`
- `pyright`
- `vulture`
- `radon`
- `bandit`
- `pip-audit`

## Interactive and debugging
- `ipython`

## App and API tooling
- `fastapi`
- `uvicorn`
- `httpx`
- `python-dotenv`
- `typer`

## Build and packaging
- `pyinstaller`

## Data and utility tools
- `sqlite-utils`
- `tabulate`

## Repo automation
- `pre-commit`
- `nox`

## Shared local editable toolchain
- `security-gateway`
- `memory-optimizer`

## Notes
- The shared local editable source is currently at [J:\_shared_toolchains\Shared-Python-Toolchain](J:/_shared_toolchains/Shared-Python-Toolchain).
- The GitHub-backed repo copy is currently in [J:\sturdy-spork\Shared-Python-Toolchain](J:/sturdy-spork/Shared-Python-Toolchain).
- The most useful recent additions were `ipython`, `pytest-xdist`, `nox`, and `radon`.

## Example commands
- Run tests:
  `py -3.13 -m pytest`
- Run tests in parallel:
  `py -3.13 -m pytest -n auto`
- Run coverage:
  `py -3.13 -m pytest --cov`
- Lint:
  `py -3.13 -m ruff check .`
- Type check with mypy:
  `py -3.14 -m mypy .`
- Type check with pyright:
  `py -3.14 -m pyright`
- Find dead code:
  `vulture .`
- Check code complexity:
  `radon cc . -s`
- Open an interactive shell:
  `ipython`
- Build a package:
  `py -3.13 -m build`
- Build a PyInstaller app:
  `pyinstaller your_app.spec`
- Sync pinned dependencies:
  `pip-sync`
- Run repo automation:
  `nox`
- Run the shared CLI tools:
  `security-gateway --help`
  `memory-optimizer --help`

## Best defaults for your repos
- Most Python repos on `J:`:
  `py -3.13 -m pytest`
- Faster test runs on larger repos:
  `py -3.13 -m pytest -n auto`
- For repos using the shared codex/security toolchain:
  `security-gateway --help`
  `memory-optimizer --help`
- For quick code health on any repo:
  `py -3.13 -m ruff check .`
  `vulture .`
  `radon cc . -s`
- For projects with a `pyproject.toml`:
  `py -3.13 -m build`
- For ad hoc inspection or one-off script testing:
  `ipython`

## Repo-specific hints
- [J:\ballistic-installer-usb-copier](J:/ballistic-installer-usb-copier):
  `py -3.13 .\main.py`
  `.\build-exe.ps1`
- [J:\hunting-property-manager](J:/hunting-property-manager):
  SQLite-related work is relevant here, so `sqlite-local` MCP support is useful for this repo.
- [J:\sturdy-spork\Shared-Python-Toolchain](J:/sturdy-spork/Shared-Python-Toolchain):
  This is the repo-backed copy of the shared local toolchain.
- [J:\_shared_toolchains\Shared-Python-Toolchain](J:/_shared_toolchains/Shared-Python-Toolchain):
  This is the safe canonical local copy that your editable installs point to.
