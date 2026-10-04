# Current Status

## v1.4.6 destructive Fresh reinstall RC preparation

Published baseline: v1.4.5, source `a9a498c8c64f178d496a3f982d2e206adfc6b203`.
This RC changes only SSH Fresh installation semantics: an administrator who supplies working SSH access and confirms the host key requests a complete reset and fresh installation of the selected Standard or Lite profile.

Existing identity, credential and Panel URL inconsistencies are diagnostics, not installation permissions. The UI enables deployment after SSH verification and shows a plain destructive confirmation for existing installations. Actual SSH, host key, platform, storage, process, package and new-credential failures remain technical errors.

The Fresh reset helper validates owned cleanup paths before mutation, stops old runtime/installer/finalizer processes, retires known current-Panel Pool identities using existing credential/Membership/Carrier transactions, clears local product state, then allocates a new UUID. Historical traffic/audit remain. Host-local claim directories and previous deployments to the same verified SSH target identify stale candidates; a public IP or foreign credential ID alone never authorizes retirement of another Node. New Nodes do not inherit Membership or Carrier assignments.

After destructive reset, failure retires and clears the failed new candidate; retry repeats reset. It never restores the old Node. The original exact-identity uninstall and legacy upgrade contracts remain unchanged. No schema, Rule/Carrier model, protocol, ACME or migration change is authorized. The existing one-time upgrader remains pinned to its published version.

Config Protocol 10 and Lifecycle Protocol 1 remain. Physical TEST and exact-HEAD Formal Independent Review are separate gates, currently pending. v1.4.6 publication and Production access are not authorized.
