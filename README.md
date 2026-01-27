# Universal PHP Form Action

A single, drop‑in `form-action.php` you can reuse across sites to process HTML contact forms (data‑only and file uploads). It includes defense‑in‑depth anti‑abuse (reCAPTCHA v3, honeypot, minimum fill time, rate limiting), reliable email delivery (SMTP via PHPMailer with `mail()` fallback), structured logs, multi‑field upload rules, JSON/redirect responses, and per‑form configuration.

> **Status:** Stable · v1.1 (multi‑file upload fields)  
> **PHP:** 7.4+ recommended (8.x tested)  
> **License:** MIT (change as needed)

---

## ✨ Features
- **One endpoint** for **plain** or **multipart** forms
- **Per‑form config**: recipients, required fields, regex rules, redirects
- **Multiple upload fields** (e.g., `id_document`, `company_documents[]`, `cv`) with per‑field max count/size/MIME, attach/persist, and optional required
- **reCAPTCHA v3** (configurable threshold per form)
- **Honeypot** + **time‑to‑complete** gate
- **Rate limiting** (IP + form) and **idempotency** (drop duplicates)
- **SMTP via PHPMailer** (auto‑detected) with `mail()` fallback
- **JSON or redirect** responses (auto‑detects AJAX)
- **Structured JSON logs** with rotation and field masking
- Optional **CSRF** (double‑submit cookie/header)
- Optional **CORS** allowlist for centralized endpoints

---

## 🗂️ Repo Structure (suggested)
```
repo/
├─ form-action.php
├─ vendor/                 # created by Composer (PHPMailer optional)
├─ uploads/                # writable; consider placing outside web root
├─ logs/                   # writable; stores logs/ratelimit/idempotency flags
│  ├─ form.log
│  ├─ ratelimit/
│  └─ idem/
├─ examples/
│  ├─ example-form-basic.html
│  └─ example-form-uploads.html
└─ docs/
   └─ SECURITY.md
```

---

## ⚙️ Requirements
- PHP 7.4+ with `fileinfo` extension
- Web server user must have **write** access to `uploads/` and `logs/`
- (Optional) Composer to install PHPMailer: `composer require phpmailer/phpmailer`

---

## 🚀 Quick Start
1. Copy `form-action.php` into your project.  
2. Create writable folders (adjust user/group):
   ```bash
   mkdir -p logs uploads logs/ratelimit logs/idem
   chown -R www-data:www-data logs uploads
   ```
3. (Optional) Install PHPMailer:
   ```bash
   composer require phpmailer/phpmailer
   ```
4. Edit the **config** at the top of `form-action.php`: SMTP creds, recipients, forms, file rules, reCAPTCHA.
5. In your form, include:
   ```html
   <input type="hidden" name="form_id" value="contact_basic">
   <input type="hidden" name="form_ts" value="<?= time() ?>"> <!-- min-fill gate -->
   <input type="text" name="company_website" style="display:none" tabindex="-1" autocomplete="off"> <!-- honeypot -->
   ```
6. (If using reCAPTCHA v3) inject token into `g-recaptcha-response` before submit.
7. Submit to `/form-action.php` and verify email/logs.

---

## 🔧 Configuration (overview)
All configuration lives near the top of `form-action.php`:

```php
$config = [
  'env'   => 'prod',
  'debug' => false,

  'allow_origins' => [ /* 'https://example.com' */ ],

  'recaptcha' => [
    'enabled'  => false,
    'secret'   => 'YOUR_RECAPTCHA_V3_SECRET',
    'threshold_default' => 0.5,
  ],

  'rate_limit' => ['window_sec' => 300, 'max_attempts' => 5],
  'idempotency' => ['ttl_sec' => 180],

  'mail' => [
    'transport'  => 'smtp', // 'smtp' | 'mail'
    'host' => 'smtp.yourhost.com', 'port' => 465, 'secure' => 'ssl',
    'username' => 'smtp-user', 'password' => 'smtp-pass',
    'from_email' => 'no-reply@example.com', 'from_name' => 'Website',
    'debug' => false, 'debug_level' => 2,
    'bcc' => [/* 'archive@example.com' */],
  ],

  'paths' => [
    'base' => __DIR__,
    'logs' => __DIR__.'/logs',
    'uploads' => __DIR__.'/uploads',
  ],

  'logging' => [
    'file' => 'form.log', 'max_bytes' => 5_000_000, 'backups' => 5,
    'mask_fields' => ['message','comments','password'],
    'retention_days' => 30,
  ],

  'security' => [
    'honeypot_field' => 'company_website',
    'min_fill_seconds' => 3,
    'csrf' => false,
    'block_domains' => ['mailinator.com','tempmail.com','10minutemail.com'],
    'max_links' => 5,
  ],

  'forms' => [ /* see below */ ],
];
```

### Per‑form config
```php
'forms' => [
  'contact_basic' => [
    'recipients' => ['hello@example.com'],
    'subject'    => '[Site] Contact Form',
    'required'   => ['name','email','message'],
    'rules'      => [ 'email' => 'email' ], // or 'regex:/^…$/'
    'redirect_success' => '/thank-you.html',
    'redirect_error'   => '/contact-error.html',
    'recaptcha_threshold' => 0.6, // overrides default

    // Link density check applies to these long-text fields
    'long_text_fields' => ['message'],

    // ✅ Multiple upload fields with per-field rules
    'files' => [
      'enabled' => true,
      'fields' => [
        'id_document' => [
          'label' => 'ID Document', 'required' => false,
          'max_files' => 1, 'max_mb' => 5,
          'allowed_mime' => ['application/pdf','image/jpeg','image/png'],
          'attach_to_mail' => true, 'persist' => false,
        ],
        'company_documents' => [
          'label' => 'Company Documents', 'required' => false,
          'max_files' => 5, 'max_mb' => 10,
          'allowed_mime' => ['application/pdf','image/jpeg','image/png'],
          'attach_to_mail' => true, 'persist' => false,
        ],
        'cv' => [
          'label' => 'Curriculum Vitae', 'required' => true,
          'max_files' => 1, 'max_mb' => 10,
          'allowed_mime' => ['application/pdf'],
          'attach_to_mail' => true, 'persist' => false,
        ],
      ],
    ],
  ],
]
```

> **Note:** Inputs can be single (`name="cv"`) or multiple (`name="company_documents[]" multiple`). The script normalizes both.

---

## 🧪 Example Form (uploads + reCAPTCHA v3)
```html
<form action="/form-action.php" method="post" enctype="multipart/form-data">
  <input type="hidden" name="form_id" value="contact_basic" />
  <input type="hidden" name="form_ts" value="<?= time() ?>" />
  <input type="text" name="company_website" style="display:none" tabindex="-1" autocomplete="off" />

  <label>Name <input name="name" required></label>
  <label>Email <input type="email" name="email" required></label>
  <label>Message <textarea name="message" required></textarea></label>

  <label>ID Document <input type="file" name="id_document" accept=".pdf,.jpg,.jpeg,.png"></label>
  <label>Company Documents <input type="file" name="company_documents[]" multiple accept=".pdf,.jpg,.jpeg,.png"></label>
  <label>CV <input type="file" name="cv" accept=".pdf" required></label>

  <input type="hidden" name="g-recaptcha-response" />
  <button type="submit">Send</button>
</form>

<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
<script>
  document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault();
    const form = this;
    grecaptcha.ready(async () => {
      const token = await grecaptcha.execute('YOUR_SITE_KEY', { action: 'submit' });
      form.querySelector('[name="g-recaptcha-response"]').value = token;
      form.submit();
    });
  });
</script>
```

---

## 🔐 Security Best Practices
- **Uploads outside web root** when possible. If under web root, deny direct access.
  - Apache `.htaccess` in `/uploads`:
    ```
    Deny from all
    ```
  - Nginx location block:
    ```nginx
    location /uploads/ { deny all; return 403; }
    ```
- Server limits: set appropriate `upload_max_filesize`, `post_max_size`, `max_file_uploads`.
- Use a domain you control for `from_email` (SPF/DKIM/DMARC alignment).
- Consider enabling **CSRF** if cross‑site risks exist.

---

## 🔒 Anti‑abuse Controls (how they work)
- **reCAPTCHA v3:** verify token server‑side; request is allowed if `score >= threshold`. Configure per form with `recaptcha_threshold`.
- **Honeypot:** hidden field must be empty. On fill, the script pretends success (quiet drop).
- **Minimum fill time:** use `form_ts`; reject if elapsed < `min_fill_seconds`.
- **Rate limit:** IP+form key → allow N attempts per window (e.g., 5 per 5 minutes).
- **Idempotency:** hash of payload+IP+UA cached for `ttl_sec`; duplicate submits within TTL are dropped.
- **Header injection guard:** subjects/headers are stripped of CR/LF.
- **Link density:** reject messages with > `max_links` URLs in designated long‑text fields.
- **Disposable domains:** configurable blocklist (e.g., Mailinator).

---

## ✉️ Email Delivery
- **PHPMailer** (auto‑used if installed) with SMTP credentials from config.
- **Fallback to `mail()`** if PHPMailer is not present.
- `Reply‑To` set to the submitter’s email when valid.
- Email body renders a table of submitted fields, **Uploaded Files** summary, and meta (IP, UA, Request‑ID, timestamp).

Install PHPMailer:
```bash
composer require phpmailer/phpmailer
```

Make sure your project’s bootstrap includes Composer’s autoloader (e.g., in your front controller or `form-action.php` if desired).

---

## 🧾 Responses
- **AJAX** (detected by `Accept: application/json` or `X-Requested-With: XMLHttpRequest` or `?json=1`):
  ```json
  { "ok": true, "message": "Thank you.", "request_id": "…" }
  ```
- **Non‑AJAX**: redirect to `redirect_success` or `redirect_error` with `?status=ok|error&rid=…`

---

## 🌐 CORS (optional)
If centralizing the endpoint across domains, add allowed origins:
```php
'allow_origins' => ['https://example.com','https://client.example'],
```
The script responds to `OPTIONS` preflights and sets CORS headers for matching origins.

---

## 🧪 Testing
**cURL (multipart, multi‑field):**
```bash
curl -i -X POST https://your.dev/form-action.php \
  -H "Accept: application/json" \
  -F form_id=contact_basic \
  -F name="Ash" \
  -F email="ash@example.com" \
  -F message="Testing multi-field uploads" \
  -F form_ts="$(date +%s -d '10 seconds ago')" \
  -F id_document=@/path/id.pdf \
  -F "company_documents[]=@/path/co-doc-1.pdf" \
  -F "company_documents[]=@/path/co-doc-2.jpg" \
  -F cv=@/path/cv.pdf
```

**Postman:** set `Body` → `form-data`, add fields just like in the cURL snippet.

---

## 🧰 Troubleshooting
- **"Captcha score too low"**: lower threshold (e.g., 0.5) and review scores in Google Admin.
- **"Failed to save uploaded file"**: check directory permissions/ownership and SELinux (`chcon -R -t httpd_sys_rw_content_t uploads logs`).
- **Rate limited during testing**: remove files in `logs/ratelimit/` for your IP.
- **No email delivered**: verify SMTP creds, firewall egress on 465/587, SPF/DKIM/DMARC alignment.
- **Need send-failure details**: check `logs/form.log*` for `submit_fail` entries; you can enable SMTP debug with `'mail' => ['debug' => true]` to log the SMTP dialogue (use briefly; it may include auth dialogue).
- **Big files rejected**: increase `upload_max_filesize`, `post_max_size`, and per‑field `max_mb`.
- **Unexpected redirect**: your request wasn’t seen as AJAX; send `Accept: application/json`.

Logs live at `logs/form.log*` (rotated). Look for your `request_id`.

---

## 🗺️ Roadmap
- Optional ClamAV scan hook
- SQLite backend for rate limit + idempotency state
- Webhook fan‑out (CRM integrations) with retry queue
- Example front‑end package (vanilla/React) to wire reCAPTCHA + CSRF

---

## 🧾 Changelog
- **v1.1** — Multiple upload fields with per‑field rules; email includes uploaded files section.
- **v1.0** — Initial release: single upload field, reCAPTCHA v3, honeypot/time gate, rate limit, idempotency, SMTP + fallback, logs, JSON/redirect responses.

---

## 📄 License
MIT © You. Feel free to adapt.
