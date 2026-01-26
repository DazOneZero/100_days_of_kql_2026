# Name
Ryuk Ransomware Registrynamevalue Creation

# Description
Detects the creation of a new Registrynamevalue, specifically one in the vein of svchost.exe

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
- T1547.001, Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder, Persistence
- T1036.005, Masquerading: Match Legitimate Resource Name or Location, Defense Evasion

# Query

```
//Ryuk Ranomware activity is observed to create run keys
//Threat actor known to use deceptive naming convention e.g., "svchos", variants are included
//The presence of scvhost.exe would be suspicious from the outset and warrant additional investigation
DeviceRegistryEvents
| where RegistryKey has "CurrentVersion\\Run"
| where RegistryValueName has_any ("svchost", "svchos", "svhost", "schost", "scvhost", "svcohst", "vshost")
| project TimeGenerated, DeviceName, RegistryValueName, RegistryValueData

```
