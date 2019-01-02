# Authorize

## What's this package do?
The authorize packages makes a binary determination of access.

Authorization is on trust from:
    - Device state (vulnerability scanned?, MDM?, BYOD? Encrypted?)
    - User standing (HR status, Groups, etc)
    - Context (time, location, role)
Driven by:
    - Dynamic "policy as code", fine grained policy
    - Machine Learning & anomaly detection based on multiple input sources