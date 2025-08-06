## Lifecycle visualized

New databroker records:

- Session Binding Request
    - Key : temporary code
    - Value : ssh client fingerprintID,  metadata about incoming connection
- Session Binding:
    - Key : ssh client fingerprint ID
    - Value : expiry, "parent" oauth session ID, user metadata, other metedata
- Identity Binding:
    - Key: ssh client fingerprint ID
    - Value : idp, user metadata, other metadata

<hr/>

one-to-many relationships:
- fingerprintID --> code (SBRs)
- session ID --> session binding ID


## Auth flow

```mermaid
flowchart TD

client[SSH Client]
authorization{Check if authorized}
sshStream[SSH Stream]
close[Close SSH Stream]

invalidateSbr[[Delete ALL related Session Bindings]]
codeFlow[Go to bespoke code flow]

existsSession{Check if the Session Binding is associated with a valid Session}
existsSessionBinding{Check if there is a valid SessionBinding}





client-->|Indexed by fingerprint|existsSessionBinding
existsSessionBinding-->|Yes|existsSession
existsSession -->|No|invalidateSbr
invalidateSbr -->codeFlow
existsSession-->|Yes|authorization
authorization-->|Allow|sshStream
authorization-->|Deny|close

```

## Bespoke Code Flow

```mermaid
flowchart TD
client[SSH Client]
lease{Lease exists?}
createSbr["Creates Session Binding Request(SBR) with randomly generated code as ID"]
waitCode[[Wait for code sync -- fetch related SBR]]
prompt[Prompt user with code]
codeDecision{Code is handled in browser}
createSB[Create Session Binding with id fingerprint ID]
af[Go to Auth flow]
waitForPromptResult{Wait for prompt result}

invalidateSbr[Delete current SBR]
close[Close SSH stream]

client-->|By fingerprint ID|lease
lease-->|No|createSbr
createSbr-->waitCode
lease-->|Yes|waitCode
waitCode-->prompt
prompt-->codeDecision
codeDecision-->|Deny|invalidateSbr
codeDecision-->|Allow|createSB
prompt-->waitForPromptResult
waitForPromptResult-->|current SBR deleted / invalid?|close
waitForPromptResult-->|session binding matching fingerprint id created?|af
```


## Revoke session flow

```mermaid
flowchart LR
sessionPage[Session Page]-->|lists by session ID|s[[Session Bindings]]
user[User revokes SSH session]
hasIB{Session binding has identity binding?}
deleteIB[Delete Identity binding]
deleteSB[Delete Session binding]

user-->|by session ID|hasIB
hasIB-->|yes|deleteIB
hasIB-->|no|deleteSB
```

## Background tasks

```mermaid

flowchart LR

deleteIB[\On Identity Binding delete\]
deleteSession[\On oauth session invalid\]
deleteAllSB[[Delete all matching Session bindings]]
close[Close related streams]

deleteSB2[\On delete session binding\]

deleteSB[Delete Session Binding]
deleteAllSBR[Delete all SBRs whose expiry is before the Session's issued date]

deleteSession-->deleteAllSB & close
deleteSB-->deleteAllSBR & close
deleteAllSB-->|for each|deleteSB
deleteSB2-->deleteSB
deleteIB-->|delete SB with matching ID|deleteSB


```
