# Repository Guidelines

## Project Structure & Module Organization
- `form-action.php` is the single runtime entry point and contains all config, helpers, and request handling.
- `README.md` is the primary documentation and includes recommended runtime directories (`logs/`, `uploads/`) and usage examples.
- `LICENSE` is MIT.
- Runtime-only directories (`logs/`, `uploads/`, `vendor/`) are not in this repo but are expected in consuming projects.

## Build, Test, and Development Commands
- No build system or framework is used; this is a standalone PHP script.
- Syntax check: `php -l form-action.php`.
- Local dev server (optional): `php -S localhost:8000` and POST to `/form-action.php`.
- Optional dependency: `composer require phpmailer/phpmailer` to enable SMTP via PHPMailer.
- Manual test (from README): use `curl -F` with form fields and files to verify JSON responses, uploads, and email.
  ```bash
  curl -i -X POST http://localhost:8000/form-action.php \
    -H "Accept: application/json" \
    -F form_id=contact_basic \
    -F name="Ash" -F email="ash@example.com" -F message="Test" \
    -F form_ts="$(date +%s -d '10 seconds ago')" \
    -F cv=@/path/cv.pdf
  ```

## Coding Style & Naming Conventions
- Language: PHP 7.4+ with `declare(strict_types=1);` at the top.
- Use `snake_case` for functions and variables (e.g., `is_json_request`, `client_ip`).
- Keep configuration in the `$config` array near the top; prefer adding options there over scattered globals.
- Indentation mixes spaces and tabs in `form-action.php` (top-level config keys are space-indented; many nested blocks use tabs); match the surrounding block and avoid reformatting unrelated lines.
- Keep helpers in the same file; avoid introducing new classes unless the script grows significantly.

## Testing Guidelines
- There is no automated test suite in this repo.
- Validate behavior with curl/Postman and check `logs/form.log*` output plus email delivery.
- When testing rate limiting/idempotency, clear state files under `logs/ratelimit/` and `logs/idem/` as needed.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative sentences (e.g., "Update README.md", "Added support for multiple file upload fields").
- PRs should include: a concise summary, any config changes, and a test note (curl command or manual steps).
- If behavior changes affect security (uploads, CSRF, CAPTCHA, rate limiting), call it out explicitly.

## Security & Configuration Tips
- Do not commit secrets (SMTP creds, reCAPTCHA keys). Use placeholders in examples.
- Prefer `uploads/` outside web root; if not possible, add web server deny rules as documented in README.
