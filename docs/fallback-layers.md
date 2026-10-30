# Three customer-controlled fallback layers

**Echo is the default defensive response mode in this proposed deployment layout.** It means bounded same-socket byte reflection—not real commands, a callback, a remote loop, an unlimited hold or an attempt to break a visitor's tools. Each layer must be independently approved, isolated and tested before exposure.

This repository has a working bounded echo service and non-executing analysis options. It does **not** currently have an automatic VM/desktop provisioning adapter, a verified remote failover controller, a floating-IP/proxy deployment or a live PC-Free backup. Untrusted logs cannot declare a backend verified, select an outbound destination, grant permission or trigger paid provisioning.

## Primary — verified customer analysis VM

Prepare a disposable guest on a separate analysis host as described in [manual VM setup](vm-setup.md). Host control, outside-guest evidence, ingress/egress rules and resource/time limits remain with an independent trusted controller. Real dynamic execution stays unavailable until that backend is implemented and verified; a detector claiming a compromise is not permission to execute anything or create a VM.

The guest may run bounded echo instead of any interpreter. With no guest NIC, only inside-guest tests can reach it. Receiving outside visitor traffic requires an independently reviewed ingress proxy/broker that does not expose host credentials or management consoles. This repository does not silently add that route.

## Backup — PC-Free is a candidate, not a trusted ready backend

The user-selected [PC-Free repository](https://github.com/jephersonRD/PC-Free) describes a Windows desktop using the upstream [`dockurr/windows` runtime](https://github.com/dockur/windows) and Codespaces/Docker. The upstream runtime runs a Windows VM with KVM acceleration; this is not simply a normal Windows application container. Its host-facing device/capability and management paths still need hardening.

The published PC-Free example requests `NET_ADMIN`, exposes KVM/TUN devices, uses unpinned images, maps management/RDP ports without loopback addresses, mounts writable persistent data and sets `restart: always`. Its troubleshooting suggests making a Codespaces port public. **Do not copy those defaults into an emergency containment layer.** No workflow, desktop, public port, image or script from this repository was run or installed during this work.

Before a customer can treat a PC-Free-derived environment as backup, independently review and pin the source/image, confirm Windows licensing, use a separate dedicated host/account with no production/cloud credentials, restrict management access, disable unneeded host sharing/passthrough, prevent guest egress to real systems, define disposable storage and outside-guest evidence retention, impose resource/deadline/billing limits and validate shutdown after controller failure. Reject unsafe settings rather than adding `privileged: true` to make it boot. Default/admin credentials, AD autojoin, arbitrary `COMMAND`, OEM install scripts and guest shared folders are not appropriate for a containment baseline.

GitHub documents that **public forwarded ports need no authentication** and that private ports have account access controls [1]. Codespaces compute/storage have quotas and possible charges; the project's “100% free” description is not a billing guarantee [2]. Required KVM/nested virtualization must be verified on the chosen host [3]. Keep this backup **disabled/unverified** until these requirements and an independent controller are actually satisfied. Metadata or a README checkbox is not an attestation.

For a separately provisioned, hardened Windows guest, the bounded mirror can run with Python 3.10+ from the reviewed package. The direct Python module avoids assuming a Unix shell launcher exists:

```powershell
# Run only inside the customer-approved isolated guest, with a minimal environment.
python -m reverse_shell_decoy.honeypot --response-mode mirror --host 127.0.0.1 --port 8022 --max-runtime 30 --max-sessions 1 --max-sessions-total 2 --max-commands 5 --session-timeout 5 --idle-timeout 2 --max-input-bytes-total 4096 --max-output-bytes-total 4096 --max-session-input-bytes 2048 --commands-per-second 1
```

This is a manual opt-in service command, not a claim that PC-Free was deployed or that its Windows configuration was tested. Start only with explicit permission in that environment. Never reuse guest desktop login secrets in the mirror or pass customer/provider keys to it. Loopback only permits local tests; reviewed inbound routing is a separate authorization.

## Emergency — separate finite echo/sink

An independently isolated, customer-owned decoy can run the existing [bounded MIRROR](mirror.md) or [30-second silent emergency profile](emergency.md). Start it explicitly; it does not inherit the failed agent's privileges, provision a host, hijack another socket or repair a compromised device. Preserve limited metadata/hashes and close at the configured caps. Revoked authorization or an integrity failure stops the local optional job; it does not authorize an emergency deployment.

A “floating listener” needs a trusted network/proxy layer and real health/ownership checks. The service cannot migrate an existing TCP file descriptor between unrelated machines by itself. This repository does not redirect a visitor to their own listener or dial a third-party endpoint.

## What a failure means

The safe immediate response is to stop the protected operation, withhold execution/export, preserve the supported error context and require fresh permission for a separately verified environment. No automatic fallback to an unverified Windows desktop, no automatic resource purchase and no silent on-host execution. A real VM escape or a compromised controller/host requires independent incident response; local Python gates and hashes cannot prove that environment safe.

## References

[1]: https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace "GitHub Codespaces forwarded-port visibility and access"
[2]: https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-codespaces/about-billing-for-github-codespaces "GitHub Codespaces quotas and compute/storage billing"
[3]: https://github.com/dockur/windows "Windows VM runtime requirements, devices and administration options"
[4]: https://github.com/jephersonRD/PC-Free "User-selected PC-Free project and published setup"
