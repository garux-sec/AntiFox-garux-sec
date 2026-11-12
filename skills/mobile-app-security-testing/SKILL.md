---
name: mobile-app-security-testing
description: Professional skills and methodology for mobile application security testing
version: 1.0.0
---

# Mobile Application Security Testing

## Overview

Mobile application security testing is an important part of ensuring the security of mobile apps. This skill provides the methods, tools, and best practices for mobile application security testing, covering both the Android and iOS platforms.

## Testing Scope

### 1. Application Security

**Checklist items:**
- Code obfuscation
- Anti-decompilation protection
- Anti-debugging protection
- Certificate pinning

### 2. Data Security

**Checklist items:**
- Data encryption
- Key management
- Sensitive data storage
- Data transmission

### 3. Authentication and Authorization

**Checklist items:**
- Authentication mechanism
- Token management
- Biometric authentication
- Session management

### 4. Communication Security

**Checklist items:**
- TLS/SSL configuration
- Certificate validation
- API security
- Man-in-the-middle attack protection

## Android Security Testing

### Static Analysis

**Using APKTool:**
```bash
# Decompile APK
apktool d app.apk

# View AndroidManifest.xml
cat app/AndroidManifest.xml

# View Smali code
find app/smali -name "*.smali"
```

**Using Jadx:**
```bash
# Decompile APK
jadx -d output app.apk

# View Java source
find output -name "*.java"
```

**Using MobSF:**
```bash
# Launch MobSF
docker run -it -p 8000:8000 opensecurity/mobsf

# Upload the APK for analysis
# Visit http://localhost:8000
```

### Dynamic Analysis

**Using Frida:**
```javascript
// Hook a function
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("[*] onCreate called");
        this.onCreate(savedInstanceState);
    };
});
```

**Using Objection:**
```bash
# Launch Objection
objection -g com.example.app explore

# Hook a function
android hooking watch class_method com.example.MainActivity.onCreate
```

**Using Burp Suite:**
```bash
# Configure the proxy
# Point the Android proxy setting to Burp Suite
# Install the Burp certificate
```

### Common Vulnerabilities

**Hardcoded keys:**
```java
// Insecure code
String apiKey = "1234567890abcdef";
String password = "admin123";
```

**Insecure storage:**
```java
// Storing sensitive data in SharedPreferences
SharedPreferences prefs = getSharedPreferences("data", MODE_WORLD_READABLE);
prefs.edit().putString("password", password).apply();
```

**Certificate validation bypass:**
```java
// Not validating the certificate
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
    }
};
```

## iOS Security Testing

### Static Analysis

**Using class-dump:**
```bash
# Export header files
class-dump app.ipa

# View header files
find app -name "*.h"
```

**Using Hopper:**
```bash
# Use Hopper to disassemble
# Open the app binary
# Analyze the assembly code
```

**Using otool:**
```bash
# View Mach-O information
otool -L app

# View strings
strings app | grep -i "password\|key\|secret"
```

### Dynamic Analysis

**Using Frida:**
```javascript
// Hook an Objective-C method
var className = ObjC.classes.ViewController;
var method = className['- login:password:'];
Interceptor.attach(method.implementation, {
    onEnter: function(args) {
        console.log("[*] Login called");
        console.log("Username: " + ObjC.Object(args[2]).toString());
        console.log("Password: " + ObjC.Object(args[3]).toString());
    }
});
```

**Using Cycript:**
```bash
# Attach to the process
cycript -p app

# Execute a command
[UIApplication sharedApplication]
```

### Common Vulnerabilities

**Hardcoded keys:**
```objective-c
// Insecure code
NSString *apiKey = @"1234567890abcdef";
NSString *password = @"admin123";
```

**Insecure storage:**
```objective-c
// Improper Keychain storage
NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
[defaults setObject:password forKey:@"password"];
```

**Certificate validation bypass:**
```objective-c
// Not validating the certificate
- (void)connection:(NSURLConnection *)connection 
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] 
          forAuthenticationChallenge:challenge];
}
```

## Tool Usage

### MobSF

```bash
# Launch MobSF
docker run -it -p 8000:8000 opensecurity/mobsf

# Upload the app for analysis
# Supports both Android and iOS
```

### Frida

```bash
# Install Frida
pip install frida-tools

# Run a script
frida -U -f com.example.app -l script.js
```

### Objection

```bash
# Install Objection
pip install objection

# Launch Objection
objection -g com.example.app explore
```

### Burp Suite

**Configure the proxy:**
1. Configure the Burp Suite listener
2. Set the proxy on the mobile device
3. Install the Burp certificate
4. Intercept and analyze traffic

## Testing Checklist

### Application Security
- [ ] Code obfuscation check
- [ ] Anti-decompilation protection
- [ ] Anti-debugging protection
- [ ] Certificate pinning

### Data Security
- [ ] Data encryption check
- [ ] Key management
- [ ] Sensitive data storage
- [ ] Data transmission security

### Authentication and Authorization
- [ ] Authentication mechanism testing
- [ ] Token management
- [ ] Session management
- [ ] Biometric authentication

### Communication Security
- [ ] TLS/SSL configuration
- [ ] Certificate validation
- [ ] API security testing
- [ ] Man-in-the-middle attack protection

## Common Security Issues

### 1. Hardcoded Keys

**Problem:**
- Hardcoded API keys
- Hardcoded passwords
- Hardcoded encryption keys

**Remediation:**
- Use a key management service
- Use environment variables
- Use secure storage

### 2. Insecure Storage

**Problem:**
- Storing sensitive data in plaintext
- Using insecure storage methods
- Data not encrypted

**Remediation:**
- Use encrypted storage
- Use Keychain/Keystore
- Implement data encryption

### 3. Certificate Validation Bypass

**Problem:**
- Not validating SSL certificates
- Accepting self-signed certificates
- Certificate pinning not implemented

**Remediation:**
- Implement certificate pinning
- Validate the certificate chain
- Use the system certificate store

### 4. Debug Information Leakage

**Problem:**
- Logs contain sensitive information
- Error messages leak information
- Debug mode not disabled

**Remediation:**
- Remove debug code
- Restrict log output
- Disable debugging in production

## Best Practices

### 1. Code Security

- Implement code obfuscation
- Disable debugging features
- Implement anti-debugging protection
- Use certificate pinning

### 2. Data Security

- Encrypt sensitive data
- Use secure storage
- Implement key management
- Restrict data access

### 3. Communication Security

- Use TLS/SSL
- Implement certificate pinning
- Validate the server certificate
- Use secure APIs

### 4. Authentication Security

- Implement strong authentication
- Secure token management
- Implement session management
- Use biometric authentication

## Notes

- Only perform testing in authorized environments
- Comply with laws and regulations
- Be aware of differences between platforms
- Protect user privacy
