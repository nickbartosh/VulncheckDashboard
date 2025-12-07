<!-- Copilot / AI agent instructions for VulncheckDashboard -->
# VulncheckDashboard — AI coding agent notes

Purpose: quick, actionable guidance so an AI coder can be immediately productive in this repo.

- **Big picture**: This is a small Flask web app that stores assets and synchronizes vulnerabilities from an external VulnCheck API. The app uses a local SQLite DB (`vulncheck.db` by default), server-side templates in `templates/`, and a thin API wrapper in `vulncheck_api.py`.

- **Major components**:
  - `app.py`: single-entry Flask application. Contains routes, DB init (`init_database()`), synchronization logic (`sync_vulnerabilities_for_asset`), PDF export (`create_vulns_pdf`), and Flask-Login integration.
  - `vulncheck_api.py`: wrapper class `VulnCheckAPI` for all external API calls. Methods return JSON or `{'error': ...}` on failure.
  - `user.py`: minimal `User` model used by Flask-Login.
  - `templates/`: Jinja2 templates for all pages (`dashboard.html`, `inventory.html`, etc.).

- **Data flow / service boundaries**:
  - Request lifecycle: `@app.before_request` creates `g.vulncheck_api` and `get_db()` uses `g.db` (SQLite connection). Close handled in `@app.teardown_appcontext`.
  - External calls: all calls to the remote vulnerability provider go through `VulnCheckAPI`. Handle returned `{'error': ...}` values instead of exceptions.
  - Persistence: raw SQL via `sqlite3` with `row_factory` and `dict_from_row` helper; vulnerabilities and assets are relationally linked via `asset_id` foreign key.

- **How to run locally (exact, reproducible steps)**
  1. Provide env vars in `.env` or environment: `SECRET_KEY`, `VULNCHECK_API_KEY` (required for sync), optionally `VULNCHECK_BASE_URL`, `DATABASE_PATH`.
  2. Use the included virtualenv interpreter: `./vulns/bin/python app.py` or create your own venv and `pip install -r requirements.txt` then `python app.py`.
  3. The app calls `init_database()` when run as `__main__` so the SQLite DB and a default `admin/admin123` user will be created on first run.

- **Important conventions & project-specific patterns**
  - Error style: external API errors are surfaced as dictionaries with an `error` key (e.g. `{'error': '...'}); calling code checks `'error' in result`.
  - DB usage: the app uses `sqlite3` with raw SQL. Use `get_db()` to obtain the request-local connection and `dict_from_row()` to convert rows to dicts.
  - Authentication: uses `Flask-Login`; `user_loader` queries `users` table and constructs `User(id, username, email)`.
  - Flash categories: UI uses `'success'` and `'error'` flash categories — keep consistent when adding messages.
  - PDF exports: `create_vulns_pdf()` uses ReportLab; generate table-friendly descriptions (truncate long descriptions in table cells).

- **Places to look for examples / editing patterns**
  - Syncing workflow: `sync_vulnerabilities_for_asset` in `app.py` — shows how to call `VulnCheckAPI.search_vulnerabilities_by_cpe`, then `get_vulnerability_info` and `get_exploit_info`.
  - API wrapper: `vulncheck_api.py` demonstrates request structure and error handling for external calls.
  - DB schema: `init_database()` in `app.py` documents fields for `users`, `assets`, `vulnerabilities` — consult this when updating queries.

- **Testing / debugging tips (repo-specific)**
  - No test suite present. For manual verification: run `python app.py` and use the web UI at `http://127.0.0.1:5000`.
  - To debug API calls, `app.logger.info()` is used in several places (e.g. during sync). Increase logging or add more `app.logger` lines for deeper inspection.
  - To avoid hitting the real API during dev, stub `VulnCheckAPI._make_request` to return a sample payload.

- **Security & operational notes**
  - Default admin is created with password `admin123` by `init_database()` — change before opening to public.
  - `SECRET_KEY` must be set via env for session security; the code reads `os.getenv('SECRET_KEY')`.
  - Rate limiting / retries: the current `VulnCheckAPI` has no retry/backoff; treat remote calls as potentially flaky and add retries where appropriate.

- **When editing code, prefer**
  - Minimal invasive changes to `app.py`: it's a single monolith file. For larger features factor code into modules (e.g., `services/`, `db/`) but keep patterns consistent with existing raw SQL usage.
  - Keep template variable names consistent (`stats`, `assets`, `vulnerabilities`) to avoid breaking views.

If anything here is unclear or you'd like more detail (example stub payloads for `VulnCheckAPI`, a recommended test harness, or a suggested refactor plan), tell me which section to expand.
