#!/bin/bash
# dvwa-init.sh — entrypoint wrapper for the modern digininja/DVWA image.
#
# The image expects an external MySQL/MariaDB (DB_SERVER) and does NOT create
# the DVWA tables itself — setup.php's create_db does, guarded by a CSRF token.
# Without the tables, admin/password login silently fails and every Clinkz
# engagement crawls an unauthenticated session and sees only login.php.
#
# We background a create_db POST once Apache is serving: GET setup.php for a
# session + user_token, then POST create_db with that token, retrying until the
# external DB is ready and admin login is verified. The image ships php (no curl
# or wget), so the HTTP flow is driven with PHP (allow_url_fopen is on).

init_dvwa_db() {
    # Wait up to ~90s for Apache to serve the login page.
    for _ in $(seq 1 90); do
        if php -r '$c=@file_get_contents("http://127.0.0.1/login.php"); exit(($c===false||$c==="")?1:0);' 2>/dev/null; then
            break
        fi
        sleep 1
    done
    # POST create_db (with a fresh token) and verify admin login. Retry against
    # transient DB warmup — the external MariaDB may not be ready immediately.
    for _ in $(seq 1 60); do
        php -r '
            $o = @file_get_contents("http://127.0.0.1/setup.php");
            $sid = null;
            foreach (($http_response_header ?? []) as $h) {
                if (preg_match("/^Set-Cookie:\s*PHPSESSID=([^;]+)/i", $h, $m)) $sid = $m[1];
            }
            if ($o === false || !$sid || !preg_match("/name=.user_token.\s+value=.([0-9a-f]+)/", $o, $t)) exit(1);
            $ctx = stream_context_create(["http" => ["method" => "POST",
                "header" => "Content-Type: application/x-www-form-urlencoded\r\nCookie: PHPSESSID=$sid\r\n",
                "content" => http_build_query(["create_db" => "Create / Reset Database", "user_token" => $t[1]]),
                "timeout" => 30, "ignore_errors" => true]]);
            @file_get_contents("http://127.0.0.1/setup.php", false, $ctx);
        ' 2>/dev/null
        if php -r '
            $o = @file_get_contents("http://127.0.0.1/login.php");
            $sid = null;
            foreach (($http_response_header ?? []) as $h) {
                if (preg_match("/^Set-Cookie:\s*PHPSESSID=([^;]+)/i", $h, $m)) $sid = $m[1];
            }
            if ($o === false || !$sid || !preg_match("/name=.user_token.\s+value=.([0-9a-f]+)/", $o, $t)) exit(1);
            $ctx = stream_context_create(["http" => ["method" => "POST",
                "header" => "Content-Type: application/x-www-form-urlencoded\r\nCookie: PHPSESSID=$sid\r\n",
                "content" => http_build_query(["username" => "admin", "password" => "password", "Login" => "Login", "user_token" => $t[1]]),
                "timeout" => 20, "ignore_errors" => true, "follow_location" => 0]]);
            @file_get_contents("http://127.0.0.1/login.php", false, $ctx);
            $loc = "";
            foreach (($http_response_header ?? []) as $h) {
                if (preg_match("/^Location:\s*(.*)$/i", $h, $l)) $loc = trim($l[1]);
            }
            exit(strpos($loc, "index.php") !== false ? 0 : 1);
        ' 2>/dev/null; then
            echo "[dvwa-init] database created — admin login verified"
            return
        fi
        sleep 2
    done
    echo "[dvwa-init] WARNING: could not verify DVWA DB init after retries"
}
init_dvwa_db &

# Hand off to the image's real entrypoint (PHP setup) + command (Apache).
exec docker-php-entrypoint apache2-foreground
