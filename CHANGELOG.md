# Changelog

## [Unreleased]

- PPPSYS-56851 Require Python 3.10 or newer (3.9 and older are end-of-life); CI tests 3.10 through 3.14
- PPPSYS-56851 Migrated packaging and CI from Poetry to uv (PEP 621, setuptools, committed `uv.lock`); PyPI releases use `uv publish`.
- PPPSYS-56851 Added local multi-version testing with tox (`tox.ini`, environments `py310`–`py314` aligned with CI); optional `dev-local` uv dependency group installs tox and tox-uv (see README).
- PPPSYS-56851 Replaced legacy Black/Flake8/isort GitHub Action with **Ruff** (`ruff check` / `ruff format --check` in CI; configuration in `pyproject.toml`).
- PPPSYS-56851 Serialize concurrent OAuth token initialization and harden 401 refresh retries
- PPPSYS-56851 Handle HTTP 429 using Retry-After and a shared cross-worker rate-limit window

## [5.2.1] - 2023-11-09

- PPPSYS-44518 Converted int values like `gt_ms` to strings
- DEVOPS-5661 Missing timeouts for gha workflow

## [5.2.0] - 2022-07-11

- Tuned default parameters for better performance

## [5.1.0] - 2022-06-08

- Removed Piwik OSS / Matomo branding
- Prepared PyPi upload automation

## [4.1.1] - 2022-02-09

- PPPSYS-28606 Fixing --dry-run

## [4.1.0] - 2021-12-13

- PPTT-3101 Source tracking

## [4.0.0]

- Process file globs in a sorted order (#291)
- Use new performance metric for server generation time (#260)
- Support for AWS Application and Elastic Load Balancer log formats (#280)
- Always disable queued tracking when sending requests from log import (#274)
- added support for Python 3.5 and above (#267)
- dropped support for Python 2.x (#267)
