# OWASP WSTG-INPV-02: Stored XSS Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting

## Step 1 — Find storage points

Identify where user input is STORED and later DISPLAYED to users:
comment forms, profile fields, forum posts, file names, message
subjects, address fields.

## Step 2 — Submit canary via storage point

POST the form with a unique canary in each field.

## Step 3 — Find where it renders

Visit the page where stored content is displayed.
Search for your canary — note the rendering context.

## Step 4 — Submit XSS payload appropriate to context

Same context analysis as reflected XSS (see wstg_xss_reflected skill).

## Step 5 — Verify persistence

Log out, log in as different user, visit the page — is the XSS
still there? Stored XSS affects ALL users who view the content.

## Step 6 — Document

Storage endpoint, rendering endpoint, payload, impact
(affects all users = higher severity than reflected).
