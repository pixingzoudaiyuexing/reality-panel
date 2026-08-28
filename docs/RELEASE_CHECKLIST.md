# Reality Panel v1.0.0-rc.5 Acceptance

Run this checklist on a new Debian 12 amd64 Panel VPS and a new Relay VPS.
Record command output without recording credentials, tokens, private keys, or
one-time enrollment secrets.

1. Verify fresh Debian 12 amd64 Panel host, root, systemd, disk, and firewall.
2. Run the pinned GitHub Release install command from the public README.
3. Verify `relay-panel.service` is enabled, active, and health returns 200.
4. Verify the Panel version equals the selected release tag.
5. Verify SQLite migrations and `PRAGMA integrity_check` pass.
6. Verify the frontend loads and the first-login/default-admin flow works.
7. Configure DNSMgr through Admin settings without exposing its API key.
8. Verify DNSMgr connection test and credential redaction in UI/API/logs.
9. Verify a new Relay host is clean and supports the required architecture.
10. Add the Relay through Panel Node Bootstrap with strict host-key checking.
11. Verify Node identity, permissions, systemd, reconnect, and WS online state.
12. Verify existing Group rules arrive on the new Relay after authentication.
13. Create a Reality SNI rule with the intended destination and SNI.
14. Verify the rule-authorized A record and public authoritative DNS value.
15. Verify DNS-01 challenge, certificate ACTIVE, and Nginx activation.
16. Verify camouflage fallback on `:8443` and public HTTP response.
17. Verify the Reality route is active and Relay remains L4 transparent.
18. Enable remote Reality/Xray backend Proxy Protocol receive and wait for its
    backend/Xray reload.
19. Verify runtime backend receive is enabled, then enable Relay send.
20. Verify a real client connection and the real client IP at the backend.
21. Verify diagnosis covers SNI, TCP, certificate, camouflage, and PROXY state.
22. Verify Reapply converges without changing healthy LKG or certificates.
23. Restart Panel and verify Node WS reconnect, desired state, and audit.
24. Restart Relay and verify LKG recovery, listeners, fallback, and WS.
25. Upgrade Panel in place from the RC to a later stable Release; verify data,
    Rules, DNSMgr, Node IDs, LKG, certificates, and frontend are preserved.
26. Upgrade Node through Panel; verify identity, runtime, LKG, and WS recover.

Do not treat plaintext HTTP as a failure when it is the configured
`PUBLIC_PANEL_URL` transport. Do not use real credentials in captured evidence.
