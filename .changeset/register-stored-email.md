---
'@wbce-d9/api': patch
---

Fixed public registration sending the confirmation link to the address as typed instead of the address of the account it
matched (GHSA-8xp8-xrh2-88vr). On MySQL/MariaDB, whose default collations are accent-insensitive, an accented look-alike
such as `vïctïm@example.com` matched the pending account `victim@example.com` and received its link. A resend is now
only sent when the typed address equals the stored one (ignoring case), the mail and token use the stored address, and
`verify-email` rejects a token whose address isn't exactly the stored one.
