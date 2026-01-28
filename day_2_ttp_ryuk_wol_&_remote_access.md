# Name
Ryuk Ransomware Wake-on-LAN & Remote Session

# Description
Ryuk Ransomware are reported to establish Wake-on-LAN processes and utilise remote access tools to achieve lateral movement.

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
- T1205, Traffic Signalling, Persistence
- T1563.002, Remote Service Session Hijacking: RDP Hijacking, Lateral Movement

# Query

```

// Ryuk Ransomware persistence & lateral movement behaviours
// Ryuk
// Detects Wake-on-LAN followed by initialisation of remote access tools
let WoLTraffic = 
    DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | where RemotePort in (7, 9)
    | where Protocol == "Udp"
    | project WoLTime = TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort;
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ("rdpclip.exe", "vmtoolsd.exe")
| project ProcessTime = TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| join kind=inner WoLTraffic on DeviceName
| where abs(ProcessTime - WoLTime) < 12h
| project DeviceName, WoLTime, ProcessTime, LocalIP, RemoteIP, RemotePort, FileName, ProcessCommandLine

```
