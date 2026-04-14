<?php
/**
 * Universal Form Action (data + file uploads) — v1.0
 * --------------------------------------------------
 * Features
 * - JSON or redirect responses (auto-detects AJAX)
 * - Per-form configuration (recipients, required, file rules, redirects)
 * - reCAPTCHA v3 (configurable threshold)
 * - Honeypot + time-to-fill gate
 * - IP+form rate limiting (file-based)
 * - Idempotency (drop duplicate submits within TTL)
 * - Optional CSRF (double-submit cookie or X-CSRF-Token header)
 * - SMTP via PHPMailer if available, else mail() fallback
 * - Safe file uploads (MIME whitelist, finfo, random names, outside web root ready)
 * - Structured JSON logs with rotation
 *
 * Expected hidden fields in forms:
 *  - form_id: maps to $config['forms'][<form_id>]
 *  - (optional) form_ts: unix timestamp when form rendered (for min time gate)
 *  - (optional) honeypot field: see $config['security']['honeypot_field']
 *  - (optional, if CSRF enabled) csrf_token (matches cookie 'csrf_token' or header X-CSRF-Token)
 *  - (if reCAPTCHA enabled) g-recaptcha-response
 *
 * SECURITY NOTE:
 * - Place uploads OUTSIDE web root if possible (set $config['paths']['uploads'] accordingly).
 * - Consider a .htaccess deny in the uploads dir if under web root.
 */

declare(strict_types=1);

// ---------------------------
// Configuration
// ---------------------------
$config = [
    'env'   => 'prod',           // 'dev' | 'prod'
    'debug' => false,            // if true, responses include more detail

    // CORS: set allowed origins if centralizing this endpoint across domains
    'allow_origins' => [
	// 'https://example.com',
    ],

    // reCAPTCHA v3
    'recaptcha' => [
	'enabled'  => false,
	'secret'   => 'YOUR_RECAPTCHA_V3_SECRET',
	'threshold_default' => 0.5,
    ],

    // Rate limiting & idempotency
    'rate_limit' => [
	'window_sec'   => 300,  // 5 minutes
	'max_attempts' => 5,    // per IP+form within window
    ],
    'idempotency' => [
	'ttl_sec' => 180, // drop exact duplicate submits within 3 minutes
    ],

    // Email delivery
    'mail' => [
	'transport'  => 'smtp', // 'smtp' | 'mail'
	'host'       => 'smtp.yourhost.com',
	'port'       => 465,
	'secure'     => 'ssl',  // 'ssl' | 'tls' | '' (none)
	'username'   => 'smtp-user',
	'password'   => 'smtp-pass',
	'from_email' => 'no-reply@example.com',
	'from_name'  => 'Website',
	// SMTP debug (PHPMailer only). Logs SMTP dialogue to form.log; use temporarily and avoid in production.
	'debug'      => false,
	'debug_level'=> 2, // 1-4 (PHPMailer SMTPDebug levels)
	'bcc'        => [
	    // 'archive@example.com'
	],
    ],

    // Paths (script will attempt to create)
    'paths' => [
	'base'    => __DIR__,                 // directory of this file
	'logs'    => __DIR__ . '/logs',       // JSON line logs + ratelimit + idem stores
	'uploads' => __DIR__ . '/uploads',    // where to store uploaded files
    ],

    // Logging
    'logging' => [
	'file'       => 'form.log',
	'max_bytes'  => 5_000_000, // rotate at ~5MB
	'backups'    => 5,         // keep N rotated files
	'mask_fields'=> ['message', 'comments', 'password'], // masked in logs
	'retention_days' => 30,
    ],

    // Security features
    'security' => [
	'features' => [
	    'honeypot'     => true,
	    'min_fill'     => true,
	    'csrf'         => true,
	    'rate_limit'   => true,
	    'recaptcha'    => true,
	    'block_domains'=> true,
	    'link_density' => true,
	    'idempotency'  => true,
	],
	'honeypot_field'   => 'company_website', // must be empty
	'min_fill_seconds' => 3,                 // reject if quicker (needs form_ts)
	'csrf'             => false,             // requires hidden 'csrf_token' + cookie OR header
	'block_domains'    => ['mailinator.com','tempmail.com','10minutemail.com'],
	'max_links'        => 5,                 // in long-text fields (e.g., message)
    ],

    // Per-form configurations
    'forms' => [
	// Example form config (adjust & duplicate as needed)
	'contact_basic' => [
	    'recipients' => ['hello@example.com'],
	    'subject'    => '[Site] Contact Form',
	    'required'   => ['name', 'email', 'message'],
	    'rules'      => [
		'email' => 'email',       // built-in: 'email'
		// 'phone' => 'regex:/^\+?[0-9\s\-\(\)]{7,}$/'
	    ],
	    'recaptcha_threshold' => 0.6, // overrides default if set
	    'redirect_success'    => '/thank-you.html',
	    'redirect_error'      => '/contact-error.html',
	    'files' => [
		'enabled' => true,
		// Configure each file input by HTML name attribute
		'fields' => [
		    'id_document' => [
			'label'         => 'ID Document',
			'required'      => false,             // if true, at least 1 file is required
			'max_files'     => 1,
			'max_mb'        => 5,                 // per file
			'allowed_mime'  => ['application/pdf','image/jpeg','image/png'],
			'attach_to_mail'=> true,              // attach to outgoing email
			'persist'       => false,             // keep file after sending?
		    ],
		    'company_documents' => [
			'label'         => 'Company Documents',
			'required'      => false,
			'max_files'     => 5,
			'max_mb'        => 10,
			'allowed_mime'  => ['application/pdf','image/jpeg','image/png'],
			'attach_to_mail'=> true,
			'persist'       => false,
		    ],
		    'cv' => [
			'label'         => 'Curriculum Vitae',
			'required'      => true,
			'max_files'     => 1,
			'max_mb'        => 10,
			'allowed_mime'  => ['application/pdf'],
			'attach_to_mail'=> true,
			'persist'       => false,
		    ],
		],
	    ],
	    // Which fields are considered "long text" for link-density checks
	    'long_text_fields' => ['message'],
	],
    ],
];

// ---------------------------
// Bootstrap
// ---------------------------
date_default_timezone_set('UTC');

// Ensure directories
@mkdir($config['paths']['logs'], 0775, true);
@mkdir($config['paths']['uploads'], 0775, true);
$rateDir = $config['paths']['logs'] . '/ratelimit';
$idemDir = $config['paths']['logs'] . '/idem';
@mkdir($rateDir, 0775, true);
@mkdir($idemDir, 0775, true);

// Log file path
$logFile = $config['paths']['logs'] . '/' . $config['logging']['file'];

// CORS (if configured)
if (!empty($config['allow_origins'])) {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin && in_array($origin, $config['allow_origins'], true)) {
	header('Access-Control-Allow-Origin: ' . $origin);
	header('Vary: Origin');
	header('Access-Control-Allow-Methods: POST, OPTIONS');
	header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, X-CSRF-Token');
	header('Access-Control-Allow-Credentials: true');
    }
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
	http_response_code(204);
	exit;
    }
}

// ---------------------------
// Helpers
// ---------------------------
function is_json_request(): bool {
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    $xhr    = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
    $qjson  = isset($_GET['json']) && $_GET['json'] === '1';
    return stripos($accept, 'application/json') !== false || strcasecmp($xhr, 'XMLHttpRequest') === 0 || $qjson;
}

function client_ip(): string {
    $keys = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'];
    foreach ($keys as $k) {
	if (!empty($_SERVER[$k])) {
	    $val = $_SERVER[$k];
	    if ($k === 'HTTP_X_FORWARDED_FOR') {
		$parts = explode(',', $val);
		return trim($parts[0]);
	    }
	    return $val;
	}
    }
    return '0.0.0.0';
}

function json_response(array $payload, ?string $redirectSuccess = null, ?string $redirectError = null) {
    if (is_json_request()) {
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	return;
    }
    // Non-AJAX: redirect
    $target = $payload['ok'] ? $redirectSuccess : $redirectError;
    if ($target) {
	// Append a short status + request id
	$qs = http_build_query([
	    'status' => $payload['ok'] ? 'ok' : 'error',
	    'rid'    => $payload['request_id'] ?? null
	]);
	$sep = (strpos($target, '?') === false) ? '?' : '&';
	header('Location: ' . $target . $sep . $qs);
	return;
    }
    // Fallback: plain text
    header('Content-Type: text/plain; charset=utf-8');
    echo $payload['message'] ?? ($payload['ok'] ? 'OK' : 'Error');
}

function rotate_logs(string $file, int $maxBytes, int $backups): void {
    if (!file_exists($file)) return;
    if (filesize($file) < $maxBytes) return;
    for ($i = $backups - 1; $i >= 0; $i--) {
	$src = $i === 0 ? $file : $file . '.' . $i;
	$dst = $file . '.' . ($i + 1);
	if (file_exists($src)) @rename($src, $dst);
    }
}

function log_event(string $file, array $loggingCfg, string $level, string $event, array $ctx = []): void {
    rotate_logs($file, $loggingCfg['max_bytes'], $loggingCfg['backups']);
    // Mask sensitive
    foreach (($loggingCfg['mask_fields'] ?? []) as $f) {
	if (isset($ctx[$f]) && is_string($ctx[$f])) {
	    $ctx[$f] = mb_substr($ctx[$f], 0, 6) . '…';
	}
    }
    $line = [
	'ts'    => gmdate('c'),
	'level' => $level,
	'event' => $event,
	'ctx'   => $ctx,
    ];
    @file_put_contents($file, json_encode($line) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function require_post(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
	http_response_code(405);
	header('Allow: POST, OPTIONS');
	echo 'Method Not Allowed';
	exit;
    }
}

function validate_email(string $email): bool {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function count_links_in(string $text): int {
    if ($text === '') return 0;
    $pattern = '/https?:\/\/[^\s<>"\']+/i';
    return preg_match_all($pattern, $text, $m) ?: 0;
}

function normalize_files_array(array $filesEntry): array {
    // Handles both single and multiple uploads
    $result = [];
    if (!isset($filesEntry['name'])) return $result;
    $names = (array)$filesEntry['name'];
    $types = (array)$filesEntry['type'];
    $tmp   = (array)$filesEntry['tmp_name'];
    $errs  = (array)$filesEntry['error'];
    $sizes = (array)$filesEntry['size'];
    $count = count($names);
    for ($i = 0; $i < $count; $i++) {
	$result[] = [
	    'name'     => $names[$i],
	    'type'     => $types[$i] ?? '',
	    'tmp_name' => $tmp[$i] ?? '',
	    'error'    => $errs[$i] ?? UPLOAD_ERR_NO_FILE,
	    'size'     => $sizes[$i] ?? 0,
	];
    }
    return $result;
}

function safe_filename(string $original): string {
    $base = preg_replace('/[^a-zA-Z0-9._-]+/', '_', $original);
    return trim($base, '._-') ?: 'file';
}

function random_id(int $bytes = 16): string {
    return bin2hex(random_bytes($bytes));
}

function current_action(): string {
    return $_POST['recaptcha_action'] ?? 'submit';
}

function security_feature_enabled(array $config, array $formCfg, string $feature, bool $default = true): bool {
    $global = $config['security']['features'][$feature] ?? $default;
    $form = $formCfg['security']['features'][$feature] ?? null;
    return $form === null ? (bool)$global : (bool)$form;
}

// ---------------------------
// Main
// ---------------------------
$rid = random_id(8); // request id
require_post();

// Lookup form config
$formId = $_POST['form_id'] ?? '';
if (!$formId || empty($config['forms'][$formId])) {
    $payload = ['ok' => false, 'message' => 'Invalid form configuration', 'request_id' => $rid];
    json_response($payload);
    exit;
}
$formCfg = $config['forms'][$formId];

// Collect meta
$ip  = client_ip();
$ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ref = $_SERVER['HTTP_REFERER'] ?? '';
$now = time();
$honeypotEnabled   = security_feature_enabled($config, $formCfg, 'honeypot');
$minFillEnabled    = security_feature_enabled($config, $formCfg, 'min_fill');
$csrfEnabled       = !empty($config['security']['csrf']) && security_feature_enabled($config, $formCfg, 'csrf');
$rateLimitEnabled  = security_feature_enabled($config, $formCfg, 'rate_limit');
$recaptchaEnabled  = !empty($config['recaptcha']['enabled']) && security_feature_enabled($config, $formCfg, 'recaptcha');
$blockDomainChecks = security_feature_enabled($config, $formCfg, 'block_domains');
$linkDensityChecks = security_feature_enabled($config, $formCfg, 'link_density');
$idempotencyEnabled= security_feature_enabled($config, $formCfg, 'idempotency');

// Honeypot
$honeypotField = $config['security']['honeypot_field'] ?? '';
if ($honeypotEnabled && $honeypotField && !empty($_POST[$honeypotField])) {
    log_event($logFile, $config['logging'], 'warn', 'honeypot_trigger', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId]);
    $payload = ['ok'=>true,'message'=>'Thank you.','request_id'=>$rid]; // Pretend success
    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
    exit;
}

// Time-to-fill gate
$minSec = (int)($config['security']['min_fill_seconds'] ?? 0);
if ($minFillEnabled && $minSec > 0 && isset($_POST['form_ts'])) {
    $started = (int)$_POST['form_ts'];
    if ($started > 0 && ($now - $started) < $minSec) {
	log_event($logFile, $config['logging'], 'warn', 'min_time_gate', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId,'elapsed'=>$now-$started]);
	$payload = ['ok'=>false,'message'=>'Please take a moment and try again.','request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
}

// CSRF (optional)
if ($csrfEnabled) {
    $cookie = $_COOKIE['csrf_token'] ?? '';
    $token  = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!$cookie || !$token || !hash_equals($cookie, $token)) {
	log_event($logFile, $config['logging'], 'warn', 'csrf_fail', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId]);
	$payload = ['ok'=>false,'message'=>'Security token mismatch.','request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
}

// Rate limit
if ($rateLimitEnabled) {
    $rateKey = hash('sha256', $formId . '|' . $ip);
    $rateFile = $rateDir . '/' . $rateKey . '.json';
    $window   = (int)$config['rate_limit']['window_sec'];
    $maxAtt   = (int)$config['rate_limit']['max_attempts'];

    $rateData = ['reset'=> $now + $window, 'count'=>0];
    if (is_file($rateFile)) {
	$rateData = json_decode((string)@file_get_contents($rateFile), true) ?: $rateData;
	if ($now > ($rateData['reset'] ?? 0)) {
	    $rateData = ['reset'=> $now + $window, 'count'=>0];
	}
    }
    $rateData['count']++;
    @file_put_contents($rateFile, json_encode($rateData), LOCK_EX);
    if ($rateData['count'] > $maxAtt) {
	$retry = max(1, (int)(($rateData['reset'] ?? $now) - $now));
	log_event($logFile, $config['logging'], 'warn', 'rate_limited', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId,'retry_in'=>$retry]);
	$payload = ['ok'=>false,'message'=>"Too many attempts. Try again in {$retry}s.",'request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
}

// reCAPTCHA v3 (optional)
if ($recaptchaEnabled) {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token) {
	$payload = ['ok'=>false,'message'=>'Captcha verification required.','request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
    $secret = $config['recaptcha']['secret'];
    $threshold = $formCfg['recaptcha_threshold'] ?? $config['recaptcha']['threshold_default'] ?? 0.5;

    // Verify via Google
    $verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    $post = http_build_query(['secret'=>$secret, 'response'=>$token, 'remoteip'=>$ip], '', '&');
    $resp = null;

    if (function_exists('curl_init')) {
	$ch = curl_init($verifyUrl);
	curl_setopt_array($ch, [
	    CURLOPT_POST => true,
	    CURLOPT_POSTFIELDS => $post,
	    CURLOPT_RETURNTRANSFER => true,
	    CURLOPT_TIMEOUT => 8,
	]);
	$resp = curl_exec($ch);
	curl_close($ch);
    } else {
	$resp = @file_get_contents($verifyUrl . '?' . $post);
    }

    $ok = false; $score = 0.0; $action = '';
    if ($resp) {
	$j = json_decode($resp, true);
	$ok    = (bool)($j['success'] ?? false);
	$score = (float)($j['score'] ?? 0.0);
	$action= (string)($j['action'] ?? '');
    }
    if (!$ok || $score < $threshold) {
	log_event($logFile, $config['logging'], 'warn', 'recaptcha_fail', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId,'score'=>$score,'action'=>$action]);
	$payload = ['ok'=>false,'message'=>'Captcha score too low.','request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
}

// Validate required & rules
$errors = [];
$fields = $_POST;
unset($fields['form_id'], $fields['csrf_token'], $fields['g-recaptcha-response']);
if (!empty($config['security']['honeypot_field'])) unset($fields[$config['security']['honeypot_field']]);
if (isset($fields['form_ts'])) unset($fields['form_ts']);
if (isset($fields['recaptcha_action'])) unset($fields['recaptcha_action']);

foreach (($formCfg['required'] ?? []) as $f) {
    if (!isset($fields[$f]) || trim((string)$fields[$f]) === '') {
	$errors[$f] = 'Required';
    }
}

foreach (($formCfg['rules'] ?? []) as $f => $rule) {
    if (!isset($fields[$f]) || $fields[$f] === '') continue;
    $val = (string)$fields[$f];
    if ($rule === 'email' && !validate_email($val)) {
	$errors[$f] = 'Invalid email';
    } elseif (strpos($rule, 'regex:') === 0) {
	$pattern = substr($rule, 6);
	if (@preg_match($pattern, '') === false) {
	    // bad pattern: ignore rule
	} else {
	    if (!preg_match($pattern, $val)) {
		$errors[$f] = 'Invalid format';
	    }
	}
    }
}

// Disposable domain block
if ($blockDomainChecks && isset($fields['email']) && $fields['email']) {
    $domain = strtolower((string)substr(strrchr((string)$fields['email'], '@') ?: '', 1));
    if ($domain && in_array($domain, $config['security']['block_domains'] ?? [], true)) {
	$errors['email'] = 'Please use a different email address';
    }
}

// Link density check on long text fields
$longFields = $formCfg['long_text_fields'] ?? [];
$maxLinks   = (int)($config['security']['max_links'] ?? 0);
if ($linkDensityChecks && $maxLinks > 0 && $longFields) {
    foreach ($longFields as $lf) {
	if (!empty($fields[$lf]) && is_string($fields[$lf])) {
	    $links = count_links_in($fields[$lf]);
	    if ($links > $maxLinks) {
		$errors[$lf] = 'Too many links';
	    }
	}
    }
}

if ($errors) {
    log_event($logFile, $config['logging'], 'info', 'validation_fail', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId,'errors'=>$errors]);
    $payload = ['ok'=>false,'message'=>'Please correct the highlighted fields.','errors'=>$errors,'request_id'=>$rid];
    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
    exit;
}

// Idempotency (drop duplicate) — multi-field aware
if ($idempotencyEnabled) {
    $idPayload = $fields;
    if (!empty($_FILES) && !empty($formCfg['files']['enabled']) && !empty($formCfg['files']['fields'])) {
	$idFilesMeta = [];
	foreach ($formCfg['files']['fields'] as $inputName => $_cfg) {
	    if (!isset($_FILES[$inputName])) continue;
	    $norm = normalize_files_array($_FILES[$inputName]);
	    // record original name + size for hash (not file contents)
	    $idFilesMeta[$inputName] = array_map(fn($f)=>[$f['name'] ?? '', (int)($f['size'] ?? 0)], $norm);
	}
	if ($idFilesMeta) $idPayload['__files'] = $idFilesMeta;
    }
    $idemHash = hash('sha256', json_encode($idPayload) . '|' . $ip . '|' . $ua);
    $idemFile = $idemDir . '/' . $idemHash . '.flag';
    $idemTtl  = (int)$config['idempotency']['ttl_sec'];
    if (is_file($idemFile) && (filemtime($idemFile) + $idemTtl) > $now) {
	log_event($logFile, $config['logging'], 'info', 'duplicate_submit_dropped', ['rid'=>$rid,'ip'=>$ip,'form'=>$formId]);
	$payload = ['ok'=>true,'message'=>'Thank you.','request_id'=>$rid];
	json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	exit;
    }
    @touch($idemFile);
}

// Process file uploads — multi-field
$savedFiles = []; // each: ['field','label','original','path','mime','size','attach','persist']
if (!empty($formCfg['files']['enabled']) && !empty($formCfg['files']['fields'])) {
    $blockedExt = ['php','phar','phtml','js','htm','html','svg','exe','cmd','bat','sh'];
    $finfo = new finfo(FILEINFO_MIME_TYPE);

    foreach ($formCfg['files']['fields'] as $inputName => $fCfg) {
	$label   = $fCfg['label'] ?? $inputName;
	$maxMB   = (int)($fCfg['max_mb'] ?? 5);
	$maxB    = $maxMB * 1024 * 1024;
	$maxCnt  = (int)($fCfg['max_files'] ?? 1);
	$attach  = !empty($fCfg['attach_to_mail']);
	$persist = !empty($fCfg['persist']);
	$required= !empty($fCfg['required']);
	$allowed = $fCfg['allowed_mime'] ?? [];

	if (!isset($_FILES[$inputName])) {
	    if ($required) {
		$payload = ['ok'=>false,'message'=>"$label is required.",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }
	    continue;
	}

	$items = normalize_files_array($_FILES[$inputName]);
	// Count only actual files (UPLOAD_ERR_NO_FILE are empty slots)
	$providedCount = count(array_filter($items, fn($f)=>($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
	if ($providedCount === 0 && $required) {
	    $payload = ['ok'=>false,'message'=>"$label is required.",'request_id'=>$rid];
	    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	    exit;
	}
	if ($providedCount > $maxCnt) {
	    $payload = ['ok'=>false,'message'=>"$label allows at most {$maxCnt} file(s).",'request_id'=>$rid];
	    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
	    exit;
	}

	foreach ($items as $f) {
	    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) continue;
	    if ($f['error'] !== UPLOAD_ERR_OK) {
		$payload = ['ok'=>false,'message'=>"$label upload error (code {$f['error']}).",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }
	    if (($f['size'] ?? 0) <= 0 || $f['size'] > $maxB) {
		$payload = ['ok'=>false,'message'=>"$label: each file must be ≤ {$maxMB}MB.",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }
	    $mime = $finfo->file($f['tmp_name']) ?: ($f['type'] ?? '');
	    if ($allowed && !in_array($mime, $allowed, true)) {
		$payload = ['ok'=>false,'message'=>"$label: file type not allowed ({$mime}).",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }

	    $orig = (string)($f['name'] ?? 'file');
	    $safe = safe_filename($orig);
	    $ext  = strtolower(pathinfo($safe, PATHINFO_EXTENSION));
	    if (in_array($ext, $blockedExt, true)) {
		$payload = ['ok'=>false,'message'=>"$label: executable file types are not allowed.",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }

	    $rand = random_id(12);
	    $dest = rtrim($config['paths']['uploads'], '/')."/{$formId}-{$inputName}-{$rand}-{$safe}";
	    if (!@move_uploaded_file($f['tmp_name'], $dest)) {
		$payload = ['ok'=>false,'message'=>"$label: failed to save uploaded file.",'request_id'=>$rid];
		json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
		exit;
	    }

	    $savedFiles[] = [
		'field'   => $inputName,
		'label'   => $label,
		'original'=> $orig,
		'path'    => $dest,
		'mime'    => $mime,
		'size'    => (int)$f['size'],
		'attach'  => $attach,
		'persist' => $persist,
	    ];
	}
    }
}

// Prepare email
$recipients = $formCfg['recipients'] ?? [];
if (!$recipients) {
    $payload = ['ok'=>false,'message'=>'No recipients configured.','request_id'=>$rid];
    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
    exit;
}

$subjectPrefix = $formCfg['subject'] ?? '[Website] Submission';
$subject = $subjectPrefix;
if (isset($fields['subject']) && is_string($fields['subject'])) {
    // prevent header injection
    $cleanSubject = trim(str_replace(["\r","\n"], '', $fields['subject']));
    if ($cleanSubject !== '') $subject .= ' — ' . $cleanSubject;
}

// Build HTML body
$rows = '';
foreach ($fields as $k => $v) {
    if (is_array($v)) $v = implode(', ', $v);
    $label = htmlspecialchars(ucwords(str_replace(['_','-'], ' ', (string)$k)), ENT_QUOTES, 'UTF-8');
    $value = htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $rows .= "<tr><td style=\"padding:6px 10px;border:1px solid #eee;white-space:nowrap;\">{$label}</td><td style=\"padding:6px 10px;border:1px solid #eee;\">{$value}</td></tr>";
}
$metaRows = [
    ['Request ID', $rid],
    ['IP', $ip],
    ['User-Agent', $ua],
    ['Referrer', $ref],
    ['When (UTC)', gmdate('Y-m-d H:i:s')],
];
$metaHtml = '';
foreach ($metaRows as [$l,$v]) {
    $l = htmlspecialchars($l, ENT_QUOTES, 'UTF-8');
    $v = htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $metaHtml .= "<tr><td style=\"padding:6px 10px;border:1px solid #eee;white-space:nowrap;\">{$l}</td><td style=\"padding:6px 10px;border:1px solid #eee;\">{$v}</td></tr>";
}
// Optional: group uploaded files by field to display in the email
$filesByField = [];
foreach ($savedFiles as $sf) {
    $filesByField[$sf['label']][] = $sf['original'] . ' (' . number_format($sf['size']/1024, 1) . ' KB)';
}
$filesHtml = '';
if ($filesByField) {
    $filesHtml .= '<p style="margin:16px 0 6px 0;font-weight:600;">Uploaded Files</p>';
    $filesHtml .= '<table style="border-collapse:collapse;border:1px solid #eee;">';
    foreach ($filesByField as $label => $list) {
	$labelEsc = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
	$listEsc  = htmlspecialchars(implode("\n", $list), ENT_QUOTES, 'UTF-8');
	$filesHtml .= "<tr><td style=\"padding:6px 10px;border:1px solid #eee;white-space:nowrap;\">{$labelEsc}</td><td style=\"padding:6px 10px;border:1px solid #eee;white-space:pre-line;\">{$listEsc}</td></tr>";
    }
    $filesHtml .= '</table>';
}
$bodyHtml = <<<HTML
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:14px;color:#222">
    <h2 style="margin:0 0 10px 0;font-size:18px;">Form submission: {$formId}</h2>
    <table style="border-collapse:collapse;border:1px solid #eee;">{$rows}</table>
    {$filesHtml}
    <p style="margin:16px 0 6px 0;font-weight:600;">Meta</p>
    <table style="border-collapse:collapse;border:1px solid #eee;">{$metaHtml}</table>
  </div>
HTML;

// Determine reply-to
$replyToEmail = null;
if (!empty($fields['email']) && validate_email((string)$fields['email'])) {
    $replyToEmail = (string)$fields['email'];
}

// Send email (PHPMailer if available)
$sendOk = false; $sendErr = null; $sendErrInfo = null; $sendErrType = null; $sendErrCode = null; $smtpDebug = [];
$transport = $config['mail']['transport'] ?? 'mail';
$mailerAvailable = class_exists('\\PHPMailer\\PHPMailer\\PHPMailer');
$mailerUsed = $mailerAvailable ? 'phpmailer' : 'mail';
$attachCount = count(array_filter($savedFiles, fn($sf) => !empty($sf['attach'])));
$sendCtxBase = [
    'rid' => $rid,
    'ip'  => $ip,
    'form'=> $formId,
    'mailer' => $mailerUsed,
    'mailer_available' => $mailerAvailable,
    'transport_requested' => $transport,
    'to_count' => count($recipients),
    'bcc_count' => count($config['mail']['bcc'] ?? []),
    'attachments' => $attachCount,
];
if ($transport === 'smtp') {
    $sendCtxBase['smtp'] = [
	'host' => $config['mail']['host'] ?? null,
	'port' => (int)($config['mail']['port'] ?? 0),
	'secure' => $config['mail']['secure'] ?? '',
	'auth' => true,
	'username_set' => !empty($config['mail']['username']),
    ];
}

if ($mailerAvailable) {
    try {
	$mail = new \PHPMailer\PHPMailer\PHPMailer(true);
	if ($transport === 'smtp') {
	    $mail->isSMTP();
	    $mail->Host       = $config['mail']['host'];
	    $mail->Port       = (int)$config['mail']['port'];
	    $secure           = $config['mail']['secure'] ?? '';
	    if ($secure === 'ssl' || $secure === 'tls') $mail->SMTPSecure = $secure;
	    $mail->SMTPAuth   = true;
	    $mail->Username   = $config['mail']['username'];
	    $mail->Password   = $config['mail']['password'];
	    if (!empty($config['mail']['debug'])) {
		$mail->SMTPDebug = (int)($config['mail']['debug_level'] ?? 2);
		$mail->Debugoutput = function ($str, $level) use (&$smtpDebug) {
		    $smtpDebug[] = ['level' => $level, 'message' => $str];
		};
	    }
	}
	$mail->CharSet = 'UTF-8';
	$mail->setFrom($config['mail']['from_email'], $config['mail']['from_name']);
	foreach ($recipients as $to) $mail->addAddress($to);
	foreach ($config['mail']['bcc'] as $bcc) $mail->addBCC($bcc);
	if ($replyToEmail) $mail->addReplyTo($replyToEmail);
	$mail->Subject = $subject;
	$mail->isHTML(true);
	$mail->Body = $bodyHtml;
	$mail->AltBody = strip_tags(str_replace(['</tr>','</td>'], ["\n","\t"], $bodyHtml));

	foreach ($savedFiles as $sf) {
	    if (!empty($sf['attach'])) {
		$mail->addAttachment($sf['path'], $sf['original']);
	    }
	}

	$mail->send();
	$sendOk = true;
    } catch (\Throwable $e) {
	$sendErr = 'Mailer error: ' . $e->getMessage();
	$sendErrType = get_class($e);
	$sendErrCode = $e->getCode();
	if (isset($mail) && !empty($mail->ErrorInfo)) $sendErrInfo = $mail->ErrorInfo;
    }
} else {
    // Fallback to mail()
    $boundary = 'b-' . random_id(12);
    $headers = [];
    $headers[] = 'MIME-Version: 1.0';
    $fromName = $config['mail']['from_name'];
    $fromEmail= $config['mail']['from_email'];
    $headers[] = 'From: ' . sprintf('"%s" <%s>', addslashes($fromName), $fromEmail);
    if ($replyToEmail) $headers[] = 'Reply-To: ' . $replyToEmail;
    if (!empty($config['mail']['bcc'])) {
	$headers[] = 'Bcc: ' . implode(',', $config['mail']['bcc']);
    }

    $hasAttachments = array_filter($savedFiles, fn($sf)=>!empty($sf['attach']));
    if ($hasAttachments) {
	$headers[] = 'Content-Type: multipart/mixed; boundary="' . $boundary . '"';
	$body  = "--{$boundary}\r\n";
	$body .= "Content-Type: text/html; charset=UTF-8\r\n\r\n";
	$body .= $bodyHtml . "\r\n";
	foreach ($savedFiles as $sf) {
	    if (empty($sf['attach'])) continue;
	    $data = @file_get_contents($sf['path']);
	    if ($data === false) continue;
	    $b64 = chunk_split(base64_encode($data));
	    $body .= "--{$boundary}\r\n";
	    $body .= "Content-Type: {$sf['mime']}; name=\"{$sf['original']}\"\r\n";
	    $body .= "Content-Transfer-Encoding: base64\r\n";
	    $body .= "Content-Disposition: attachment; filename=\"{$sf['original']}\"\r\n\r\n";
	    $body .= $b64 . "\r\n";
	}
	$body .= "--{$boundary}--";
    } else {
	$headers[] = 'Content-Type: text/html; charset=UTF-8';
	$body = $bodyHtml;
    }

    $toHeader = implode(',', $recipients);
    $mailWarning = null;
    set_error_handler(function ($severity, $message) use (&$mailWarning) {
	$mailWarning = $message;
	return true; // suppress default warning output
    });
    $sendOk = mail($toHeader, $subject, $body, implode("\r\n", $headers));
    restore_error_handler();
    if (!$sendOk) {
	$sendErr = 'mail() returned false';
	if ($mailWarning) $sendErr .= '; warning: ' . $mailWarning;
    }
}

// Cleanup uploaded files if not persisting
foreach ($savedFiles as $sf) {
    if (empty($sf['persist'])) {
	@unlink($sf['path']);
    }
}

// Log and respond
if ($sendOk) {
    log_event($logFile, $config['logging'], 'info', 'submit_ok', array_merge(
	$sendCtxBase,
	[
	    'to' => $recipients,
	    'bcc' => $config['mail']['bcc'] ?? [],
	]
    ));
    $payload = ['ok'=>true,'message'=>'Thank you.','request_id'=>$rid];
    if (!empty($config['debug'])) $payload['debug'] = ['rid'=>$rid];
    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
} else {
    $errCtx = array_merge($sendCtxBase, [
	'error' => $sendErr,
	'error_info' => $sendErrInfo,
	'error_type' => $sendErrType,
	'error_code' => $sendErrCode,
	'smtp_debug' => $smtpDebug ?: null,
	'bcc' => $config['mail']['bcc'] ?? [],
    ]);
    log_event($logFile, $config['logging'], 'error', 'submit_fail', $errCtx);
    $payload = ['ok'=>false,'message'=>'Sorry, something went wrong sending your message.','request_id'=>$rid];
    if (!empty($config['debug'])) $payload['debug'] = ['error'=>$sendErr,'rid'=>$rid];
    json_response($payload, $formCfg['redirect_success'] ?? null, $formCfg['redirect_error'] ?? null);
}
