---
'@wbce-d9/api': patch
---

Fixed `POST /users/invite` re-sending the invitation of an already invited user, with an unchanged role, without any
check: the caller didn't need any permission, also when unauthenticated, and an `invite_url` outside of
`USER_INVITE_URL_ALLOW_LIST` was used for the link. Re-sending now needs update access to the invited user and an
allowed `invite_url`, like an invite that changes the role.
