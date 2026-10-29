# Implementation references

The Linux detector correlates TCP connection metadata and socket inode ownership from a read-only `/proc` snapshot. `/proc/net` describes the observer's network namespace, not every container or every host connection. A snapshot alone cannot establish who initiated a connection or whether a shell is malicious. [1]

The optional Docker instructions use documented runtime flags for a read-only filesystem, dropped capabilities, privilege restrictions, no network, and container-specific CPU/memory/PID ceilings. These are defense-in-depth measures, not a claim that containers are an adequate boundary for real hostile code. This project never executes submitted commands. The Docker configuration is an example, not a deployed service. [2]

References checked on 2026-10-29. No third-party code was copied from these sources.

## References

[1]: https://man7.org/linux/man-pages/man5/proc_pid_net.5.html "Linux manual: proc_pid_net"
[2]: https://docs.docker.com/reference/cli/docker/container/run/ "Docker container run reference"
