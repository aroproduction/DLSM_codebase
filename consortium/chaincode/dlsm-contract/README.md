# DLSM Chaincode

This directory will contain the DLSM reputation and incident chaincode.

Preferred language for the prototype:

```text
TypeScript
```

Why TypeScript:

- Good structure for larger project code.
- Strong types for ledger objects.
- Easy integration with a Node.js gateway.
- Clear enough for academic demonstration.

The first chaincode milestone will implement:

```text
RegisterUser(userId, orgId, role)
GetUserReputation(userId)
```

