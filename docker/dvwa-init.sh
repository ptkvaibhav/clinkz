#!/bin/bash
# dvwa-init.sh — Entrypoint wrapper for DVWA that applies known bug fixes
# before starting Apache.
#
# Bug 1: MySQL.php line 102 closing "?>" tag causes "Cannot modify header
#         information — headers already sent" after DB creation.
# Bug 2: setup.php CSRF check prevents automated (non-browser) DB init.

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

# Hand off to the original entrypoint / CMD
exec /main.sh
