# Name
Hidden User Account Creation

# Description
This threat actor creates hidden user accounts using naming conventions such as "admin1$", "admin2$" and "power$".

# References
- https://blog.talosintelligence.com/uat-8099-new-persistence-mechanisms-and-regional-focus/

# Author
- DazOneZero
  
# Socials
- www.linkedin.com/in/darrel-lang
- @PrimisResolvere

# Threats
- UAT-8099 / Chinese cybercrime

# MITRE Techniques
- T1564, Hide Artifacts: Hidden Users, Defense Evasion

# Query

```

// UAT-8099
// Detects the creation of hidden users by appending a '$' at the end of a newly created user
DeviceProcessEvents
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "user" 
    and ProcessCommandLine has "/add" 
    and ProcessCommandLine contains "$"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| sort by TimeGenerated desc

```
