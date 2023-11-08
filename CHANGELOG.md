# Changelog

## [Unreleased]

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
