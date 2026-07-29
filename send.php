<?php
declare(strict_types=1);

/**
 * AIISC website contact endpoint.
 *
 * Security design notes (please read before editing):
 *
 * 1. NO USER INPUT EVER REACHES AN EMAIL HEADER except the Reply-To address,
 *    which is validated. The subject is a fixed string. This makes header
 *    (CRLF) injection structurally impossible rather than filtered-against.
 *    Do not "improve" this by putting the sender's name in the subject.
 *
 * 2. Because of (1), the message body does NOT need HTML escaping. The old
 *    version ran FILTER_SANITIZE_SPECIAL_CHARS over the body, which mangled
 *    legitimate mail ("O'Reilly" -> "O&#39;Reilly") and only blocked CRLF as
 *    an accident of encoding chars below ASCII 32.
 *
 * 3. Rate limits are enforced per-IP AND globally. The global cap is the one
 *    that matters: per-IP limits are bypassable with a proxy pool or any IPv6
 *    /64, so the global ceiling is what actually bounds inbox damage.
 *
 * 4. State lives outside the document root. Never move it under /var/www.
 */

const RECIPIENT      = 'aiisc@mailbox.sc.edu';
const FROM_ADDRESS   = 'noreply@ifestos.cse.sc.edu';
const ALLOWED_HOSTS  = ['ai.cse.sc.edu', 'ifestos.cse.sc.edu', 'localhost'];

const STATE_DIR      = '/var/lib/aii-form';
const STATE_FILE     = STATE_DIR . '/ratelimit.json';
const LOG_FILE       = STATE_DIR . '/submissions.log';

const PER_IP_LIMIT   = 3;      // submissions per IP (or IPv6 /64) ...
const PER_IP_WINDOW  = 3600;   // ... per hour
const GLOBAL_LIMIT   = 40;     // total submissions from the whole form ...
const GLOBAL_WINDOW  = 3600;   // ... per hour. The real backstop.

const MAX_NAME       = 120;
const MAX_EMAIL      = 254;
const MAX_MESSAGE    = 4000;
const MAX_BODY_BYTES = 32768;

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

/** Emit a JSON response and stop. */
function json_out(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Rate-limit bucket for the caller.
 *
 * Uses REMOTE_ADDR only - deliberately NOT X-Forwarded-For, which is
 * client-controlled and would let an attacker mint a fresh bucket per request.
 * IPv6 is collapsed to its /64 prefix because a single host routinely controls
 * an entire /64, making per-address limiting meaningless.
 */
function client_key(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (str_contains($ip, ':')) {
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) {
            return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
        }
    }
    return $ip;
}

/**
 * Atomically check and record a submission against both limits.
 *
 * Fails CLOSED: if the state directory is missing or unwritable we refuse to
 * send. An unbounded mail endpoint is the exact failure this file exists to
 * prevent, so a broken form is the safer of the two outcomes.
 *
 * @return array{0: bool, 1: string} [allowed, reason]
 */
function rate_check(string $key): array
{
    $now = time();

    $fh = @fopen(STATE_FILE, 'c+');
    if ($fh === false) {
        error_log('aii-form: cannot open ' . STATE_FILE . ' - refusing to send');
        return [false, 'state-unavailable'];
    }

    try {
        if (!flock($fh, LOCK_EX)) {
            error_log('aii-form: cannot lock ' . STATE_FILE . ' - refusing to send');
            return [false, 'lock-failed'];
        }

        $raw   = stream_get_contents($fh);
        $state = json_decode($raw ?: '{}', true);
        if (!is_array($state)) {
            $state = [];
        }

        $perIp  = array_values(array_filter($state['ips'][$key] ?? [], fn($t) => $t > $now - PER_IP_WINDOW));
        $global = array_values(array_filter($state['global'] ?? [],   fn($t) => $t > $now - GLOBAL_WINDOW));

        if (count($global) >= GLOBAL_LIMIT) {
            return [false, 'global-limit'];
        }
        if (count($perIp) >= PER_IP_LIMIT) {
            return [false, 'ip-limit'];
        }

        $perIp[]  = $now;
        $global[] = $now;

        // Prune buckets that have aged out entirely, so the file cannot grow
        // without bound as addresses rotate.
        $ips = [];
        foreach ($state['ips'] ?? [] as $k => $stamps) {
            $live = array_values(array_filter($stamps, fn($t) => $t > $now - PER_IP_WINDOW));
            if ($live) {
                $ips[$k] = $live;
            }
        }
        $ips[$key] = $perIp;

        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode(['ips' => $ips, 'global' => $global]));
        fflush($fh);

        return [true, 'ok'];
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

/** Append one line of provenance so the next incident needs no Postfix log. */
function log_submission(string $key, string $outcome, string $email = '-'): void
{
    $line = sprintf(
        "%s\t%s\t%s\t%s\t%s\n",
        gmdate('c'),
        $key,
        $outcome,
        $email,
        substr($_SERVER['HTTP_USER_AGENT'] ?? '-', 0, 200)
    );
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

// ---------------------------------------------------------------------------
// Request checks
// ---------------------------------------------------------------------------

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    json_out(405, ['status' => 'error', 'message' => 'Method not allowed.']);
}

if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_BODY_BYTES) {
    json_out(413, ['status' => 'error', 'message' => 'Message too large.']);
}

// Same-origin check. Only enforced when the browser actually sent an Origin -
// privacy tooling legitimately strips it, so a missing header is not treated
// as hostile. This is a cheap extra layer, not a primary control.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    $host = parse_url($origin, PHP_URL_HOST) ?? '';
    if (!in_array($host, ALLOWED_HOSTS, true)) {
        json_out(403, ['status' => 'error', 'message' => 'Cross-origin submissions are not accepted.']);
    }
}

$key = client_key();

// Honeypot. Real browsers leave this hidden field empty; naive bots fill every
// input they find. Report success so the bot has no signal to adapt to, but
// send nothing.
//
// The field is deliberately NOT called "website" or "url": password managers
// autofill those, and a filled honeypot silently discards a genuine message.
if (trim((string) ($_POST['contact_ref'] ?? '')) !== '') {
    log_submission($key, 'honeypot');
    json_out(200, ['status' => 'success']);
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

$name    = trim((string) ($_POST['name'] ?? ''));
$email   = trim((string) ($_POST['email'] ?? ''));
$message = trim((string) ($_POST['message'] ?? ''));

// Note: strlen() checks are deliberate - they bound the bytes we hand to the
// MTA, which is the resource being protected, not the glyph count.
if ($name === '' || $email === '' || $message === '') {
    json_out(400, ['status' => 'error', 'message' => 'Name, email, and message are all required.']);
}
if (strlen($name) > MAX_NAME || strlen($email) > MAX_EMAIL || strlen($message) > MAX_MESSAGE) {
    json_out(400, ['status' => 'error', 'message' => 'One or more fields exceed the maximum length.']);
}

$email = filter_var($email, FILTER_VALIDATE_EMAIL);
if ($email === false) {
    json_out(400, ['status' => 'error', 'message' => 'Please enter a valid email address.']);
}

// Belt and braces. FILTER_VALIDATE_EMAIL already rejects control characters,
// so this can only fire if that behaviour ever regresses - which is precisely
// when we would want it to.
if (strpbrk($email, "\r\n") !== false) {
    log_submission($key, 'header-injection-attempt');
    json_out(400, ['status' => 'error', 'message' => 'Please enter a valid email address.']);
}

// Reject control characters in the name, excluding tab. Not a security control
// (the name never touches a header) - it just keeps the delivered mail clean.
if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $name)) {
    json_out(400, ['status' => 'error', 'message' => 'Name contains unsupported characters.']);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

[$allowed, $reason] = rate_check($key);
if (!$allowed) {
    log_submission($key, 'blocked:' . $reason, $email);

    if ($reason === 'state-unavailable' || $reason === 'lock-failed') {
        json_out(503, [
            'status'  => 'error',
            'message' => 'The contact form is temporarily unavailable. Please email aiisc@mailbox.sc.edu directly.',
        ]);
    }

    header('Retry-After: 3600');
    json_out(429, [
        'status'  => 'error',
        'message' => 'Too many messages have been sent recently. Please try again later, or email aiisc@mailbox.sc.edu directly.',
    ]);
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

// Fixed subject: no user input, so there is nothing to inject into.
$subject = 'AIISC Website Contact';

// All user-supplied data lives in the body, past the header/body boundary,
// where CRLF has no special meaning.
$body = "Name:  {$name}\n"
      . "Email: {$email}\n"
      . "IP:    {$key}\n"
      . "Time:  " . gmdate('c') . "\n"
      . "\n"
      . "Message:\n"
      . "--------\n"
      . $message . "\n";

$headers = [
    'From'                      => FROM_ADDRESS,
    'Reply-To'                  => $email,
    'Content-Type'              => 'text/plain; charset=UTF-8',
    'Content-Transfer-Encoding' => '8bit',
    'X-Mailer'                  => 'aiisc-contact',
    'Auto-Submitted'            => 'auto-generated',
];

// The -f envelope sender aligns the return-path with the From header, which
// is what SPF and DMARC evaluate. See the DNS ticket: neither record exists
// for ifestos.cse.sc.edu yet, so alignment is currently moot but harmless.
$sent = mail(RECIPIENT, $subject, $body, $headers, '-f' . FROM_ADDRESS);

if (!$sent) {
    error_log('aii-form: mail() failed for ' . $key);
    log_submission($key, 'mail-failed', $email);
    json_out(500, [
        'status'  => 'error',
        'message' => 'The message could not be sent. Please email aiisc@mailbox.sc.edu directly.',
    ]);
}

log_submission($key, 'sent', $email);
json_out(200, ['status' => 'success']);
