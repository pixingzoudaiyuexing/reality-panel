# Official Node installation profiles

Standard and Lite are both official profiles. Upgrade preserves Standard → Standard and Lite → Lite. Profile conversion is outside the version upgrade contract.

| Path | Standard | Lite |
| --- | --- | --- |
| Fresh provisioning | `lite_mode=false`, `PROFILE=standard`, `LITE_MODE=0` | `lite_mode=true`, `PROFILE=lite`, `LITE_MODE=1` |
| Fallback | Owned Xiaoya Docker container on loopback 5245, durable private ownership marker and data path | Native managed Nginx fallback on loopback 5245, marker containing `lite` |
| Legacy detection | Positive official binary/systemd and healthy owned Xiaoya evidence | Positive official binary/systemd, explicit Lite marker, managed files/listener and health |
| Legacy bundle | Saved `source_profile=standard` | Saved `source_profile=lite` |
| Ordinary update | Same identity and profile; running owned fallback reused in place | Same identity and profile; existing Lite marker retained |
| Rollback | Old binary/env/identity/managed config/marker restored, live container/config/data retained in place and checked | Old binary/env/identity/marker/managed Nginx restored |
| Uninstall | Existing ownership checks remove only verified Xiaoya resources | Existing ownership checks remove only verified Lite resources |

Official source provenance and installation profile are independent. A missing Lite marker alone is not Standard evidence; disk size is not evidence. Unknown/custom/conflicting layouts fail before STOP. No new schema or protocol was added.

v1.4.3 is an unpublished candidate. The v1.4.2 release, tag, original upgrade script and SHA256SUMS remain immutable. Do not deploy this candidate to Production as part of TEST acceptance.
