# Piwik PRO Server Log Analytics

Import your web server logs to Piwik PRO.

## Requirements

* Python 3.10 or newer (3.9 and older are end-of-life).
* Piwik PRO >= 16+, all the versions, including Cloud, Core and On-Premises are supported

## Local tests

The **`dev-local`** dependency group installs [tox](https://tox.wiki/), [pytest](https://docs.pytest.org/), and [tox-uv](https://github.com/tox-dev/tox-uv) so tox creates each Python environment with **uv** (this avoids broken venvs when a uv-managed CPython is first on `PATH`). **Tox** runs the suite under **Python 3.10–3.14** per `tox.ini` (`py310` … `py314`). There is **no committed `.python-version`** pin; **uv** picks a compatible interpreter for the project `.venv`, and you can add a **local** `.python-version` if you want (the file is **gitignored**).

```bash
uv sync --group dev-local
uv run tox
```

Use `uv run tox -e py312` for one version, or `uv run tox -- test_main.py -q` to forward arguments to pytest (paths are relative to `tests/`, same as `./run_tests.sh`). To call pytest without tox: `cd tests && PYTEST_SESSION=1 uv run pytest` (from the repo root, so log fixtures resolve).

If you skip `dev-local`, use `uvx tox` or a globally installed `tox` against this `tox.ini` (install **tox-uv** alongside tox if your default interpreter comes from uv and tox envs fail to start).

Lint and format with [Ruff](https://docs.astral.sh/ruff/) (same style as the Piwik PRO MCP repo): `uv run ruff check .` and `uv run ruff format .` (CI runs `ruff format --check`).

## Getting started

1. Download this git repository `git clone git@github.com:PiwikPRO/log-analytics.git`. The script uses only python standard library, so no external packages are required. Alternatively you can download our PyPi package - `pip install piwik-pro-log-analytics`.
2. Generate Client ID and Client Secret for communication with Piwik PRO API - docs on how to do this can be found on [developers.piwik.pro](https://developers.piwik.pro/en/latest/data_collection/other_integrations/web_log_analytics.html)
3. You are now ready to import your web server's access logs into Piwik PRO:
  * `PIWIK_CLIENT_ID=<client-id> PIWIK_CLIENT_SECRET=<client-secret> piwik_pro_log_analytics/import_logs.py --url=<my-organization>.piwik.pro /path/to/access.log`
  * The `--client-id`/`--client-secret` flags are also accepted, but are deprecated: passing them on
    the command line exposes them in your shell history and to other local users via the process
    list. Prefer the environment variables shown above.
  * If you installed log analytics via `pip`, instead of `piwik_pro_log_analytics/import_logs.py` use `piwik_pro_log_analytics`
  * If the code fails, saying, that your log format doesn't contain hostname - you must decide what App you'd like to track to. You can find App ID in Piwik PRO UI> Administration> Sites & apps>. After that, use `--idsite <app-id>` flag to tell the importer which App you'd like to track to.
![How to find App ID](docs/app-id.png "How to find App ID")


## More usage instructions
More usage instructions can be found on [developers.piwik.pro](https://developers.piwik.pro/en/latest/data_collection/other_integrations/web_log_analytics.html)


## License

Log-analytics is released under the GPLv3 or later.  Please refer to  [LEGALNOTICE](LEGALNOTICE) for copyright and trademark statements and [LICENSE.txt](LICENSE.txt) for the full text of the GPLv3.

