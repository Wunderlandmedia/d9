---
'@wbce-d9/api': patch
---

Fixed update and delete by query evaluating the `filter` without the caller's read permissions (GHSA-2xcm-7h22-3m66).
The items matched by the filter revealed values of fields the user can't read. The filter is now checked against the
user's read permissions, like a read: filtering on a field they can't read is refused with `403`, and rows they can't
read are not matched. This includes `DELETE /users` by query.

This changes nested one-to-many updates too: the related items left out of the payload (or listed in `delete`) are
looked up with the user's read permissions before being detached or deleted. A user who can't read the related
collection, or the fields of the relation, now gets a `403` for the whole update instead of detaching or deleting items
they can't see. Related items hidden from them by a read permission filter are left untouched.
