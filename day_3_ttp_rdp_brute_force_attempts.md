# Name
RDP Brute Force Attempts with Eventual Successful Login

# Description
Aim to identify higher-than-normal number of failed RDP login attempts followed by a successful login within short timeframe.

# References
- https://blog.securelayer7.net/ryuk-ransomware/#How-to-Detect-Ryuk-Attack

# Author
- DazOneZero
  
# Socials
- www.linkedin.com/in/darrel-lang
- @PrimisResolvere

# Threats
- Ryuk (Ransomware)

# MITRE Techniques
- T1110, Brute Force, Credential Access

# Query

```

// Ryuk ransomware brute force activity aimed at remote access
// Detects where number of failed RDP logins >20 is then followed by successful login
DeviceLogonEvents
| where LogonType == "RemoteInteractive" // RDP
| summarize 
    Failures = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess")
    by RemoteIP, DeviceName, bin(TimeGenerated, 30m)
| where Failures > 20 and Successes > 0

```
