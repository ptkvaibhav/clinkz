#!/bin/bash
# dvwa-init.sh — Entrypoint wrapper for DVWA that applies known bug fixes
# and creates the application database before handing off to the real CMD.
#
# Bug 1: MySQL.php line 102 closing "?>" tag causes "Cannot modify header
#         information — headers already sent" after DB creation.
# Bug 2: setup.php CSRF check prevents automated (non-browser) DB init.
# Bug 3: The base image's main.sh only starts mysqld/apache2 — it never
#         runs setup.php, so the `users` table is never created and
#         admin/password login fails. Every Clinkz engagement then crawls
#         an unauthenticated session and sees only login.php. We POST
#         create_db once Apache is up so a fresh container is login-ready.

MYSQL_PHP="/var/www/html/dvwa/includes/DBMS/MySQL.php"
SETUP_PHP="/var/www/html/setup.php"

# Fix 1: Comment out bare closing PHP tag in MySQL.php (prevents header error)
# Files have \r\n line endings so we match with optional \r
if [ -f "$MYSQL_PHP" ]; then
    sed -i 's/^?>\r\?$/\/\/?>/' "$MYSQL_PHP"
fi

# Fix 2: Comment out CSRF token check in setup.php (allow automated DB reset)
if [ -f "$SETUP_PHP" ]; then
    sed -i 's/^[\t ]*checkToken.*setup\.php.*/\/\/&/' "$SETUP_PHP"
fi

# Fix 3: Create / reset the DVWA database in the background once Apache is
# serving. The image ships neither curl nor wget, so we drive the HTTP POST
# with PHP (allow_url_fopen is on). setup.php's create_db is idempotent and
# its CSRF check is disabled by Fix 2, so a bare POST suffices.
init_dvwa_db() {
    # Wait up to ~60s for Apache to serve the login page (proxy for "web +
    # mysql up", since main.sh starts mysql before apache).
    for _ in $(seq 1 60); do
        if php -r '$c=@file_get_contents("http://127.0.0.1/login.php"); exit(($c===false||$c==="")?1:0);' 2>/dev/null; then
            break
        fi
        sleep 1
    done
    # POST create_db (retry a few times against transient mysql warmup).
    for _ in 1 2 3; do
        php -r '$ctx=stream_context_create(["http"=>["method"=>"POST","header"=>"Content-Type: application/x-www-form-urlencoded\r\n","content"=>http_build_query(["create_db"=>"Create / Reset Database"]),"timeout"=>20,"ignore_errors"=>true]]); @file_get_contents("http://127.0.0.1/setup.php",false,$ctx);' 2>/dev/null
        # Stop once admin/password can authenticate (login redirects to index).
        if php -r '$o=@file_get_contents("http://127.0.0.1/login.php"); if(preg_match("/name=.user_token. value=.([a-f0-9]{32})/",$o,$m)){} $sid=null; foreach(($http_response_header??[]) as $h){if(preg_match("/^Set-Cookie:\s*PHPSESSID=([^;]+)/i",$h,$c))$sid=$c[1];} if(!isset($m[1])||!$sid)exit(1); $ctx=stream_context_create(["http"=>["method"=>"POST","header"=>"Content-Type: application/x-www-form-urlencoded\r\nCookie: PHPSESSID=$sid\r\n","content"=>http_build_query(["username"=>"admin","password"=>"password","Login"=>"Login","user_token"=>$m[1]]),"timeout"=>20,"ignore_errors"=>true,"follow_location"=>0]]); @file_get_contents("http://127.0.0.1/login.php",false,$ctx); $loc=""; foreach(($http_response_header??[]) as $h){if(preg_match("/^Location:\s*(.*)$/i",$h,$l))$loc=trim($l[1]);} exit(strpos($loc,"index.php")!==false?0:1);' 2>/dev/null; then
            echo "[dvwa-init] database created — admin login verified"
            return
        fi
        sleep 2
    done
    echo "[dvwa-init] WARNING: could not verify DVWA DB init after retries"
}
init_dvwa_db &

# Hand off to the original entrypoint / CMD
exec /main.sh
