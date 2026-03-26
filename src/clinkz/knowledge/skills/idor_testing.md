# IDOR Testing — Exploitation Skill

How to detect and exploit Insecure Direct Object References:

## Step 1: Identify Object References

Look for parameters that reference objects by ID:
- Sequential integers: `id=1`, `user_id=42`, `order_id=1001`
- UUIDs: `id=550e8400-e29b-41d4-a716-446655440000`
- Filenames: `doc=report_2024.pdf`, `file=user_42_profile.jpg`
- Encoded values: Base64-encoded IDs, hashed references

## Step 2: Establish Your Identity

Know what YOUR object references are:
```
GET /api/profile → {"user_id": 5, "name": "testuser"}
GET /api/orders → [{"order_id": 101}, {"order_id": 102}]
```

## Step 3: Access Another User's Object

Change the ID to reference a different object:
```
GET /api/profile?user_id=1       → Returns admin's profile?
GET /api/orders/100              → Returns someone else's order?
GET /api/users/1/documents       → Returns another user's documents?
```

## Step 4: Analyze the Response

- **200 OK with different user's data** → IDOR CONFIRMED
- **200 OK with your own data** → Server ignores the parameter (uses session)
- **403 Forbidden** → Authorization check exists (not vulnerable)
- **404 Not Found** → Object doesn't exist (try other IDs)
- **200 OK with empty data** → Might be authorized but object is empty

## Step 5: Test All HTTP Methods

IDOR often exists on one method but not others:
```
GET /api/users/1     → 403 (read protected)
PUT /api/users/1     → 200 (write NOT protected!) → IDOR on update
DELETE /api/users/1  → 200 (delete NOT protected!) → IDOR on delete
```

## Step 6: Test Horizontal vs Vertical

### Horizontal IDOR (same privilege level)
```
User A (id=5) accessing User B's (id=6) data:
GET /api/users/6/profile → Returns User B's profile
```

### Vertical IDOR (privilege escalation)
```
Regular user accessing admin resources:
GET /api/admin/users        → Returns all users
GET /api/admin/settings     → Returns admin settings
PUT /api/users/5/role       → {"role": "admin"} → Privilege escalation
```

## Step 7: Predictability Analysis

- **Sequential integers**: Try id-1, id+1, id=0, id=-1
- **UUIDs**: Usually not guessable — but check if they leak elsewhere
  (API responses, HTML source, JavaScript files)
- **Encoded**: Decode the value, modify it, re-encode
- **Hashed**: Check if the hash is just MD5(id) or similar weak scheme

## Common IDOR Locations

- User profiles: `/api/users/{id}`
- Documents/files: `/api/documents/{id}`
- Orders/transactions: `/api/orders/{id}`
- Messages: `/api/messages/{id}`
- Settings: `/api/settings/{id}`
- Password reset: `/api/reset?token={token}&user_id={id}`
- File downloads: `/download?file=user_{id}_report.pdf`
