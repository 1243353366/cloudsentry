"""Manual echo-only guest workload, not a VM provisioner or traffic forwarder.

Both slots accept connections; neither ever dials a visitor/controller. Each
connection receives only its own bytes, never data from the other slot. Guest
placement, hypervisor security and ingress routing are independent controls.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import sys
from typing import Any

from .authorization import (AuthorizationError, AuthorizationGrant, AuthorizationScope,
                            cancellation_guard, request_authorization)
from .honeypot import DecoyServer
from .throttle import InboundThrottle

_CREDENTIAL_NAMES = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "CLOUDFLARE_API_TOKEN", "RENDER_API_KEY", "RAILWAY_API_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY",
})
_SERVICE_LIMITS = {
    "max_sessions": 1, "max_sessions_total": 2, "max_commands": 5,
    "idle_timeout": 2, "session_timeout": 5, "audit_limit": 32,
    "max_runtime": 30, "max_input_bytes_total": 4096, "max_output_bytes_total": 4096,
    "max_session_input_bytes": 2048, "commands_per_second": 1,
}
# One object paces both slots, so the pair cannot be used to double the admitted
# inbound rate or to reset a bucket by hopping between ports.
_PACING_LIMITS = {
    "connects_per_second": 4, "connects_per_second_per_peer": 2,
    "units_per_second": 4, "units_per_second_per_peer": 2,
}


@dataclass(frozen=True)
class EchoBindings:
    host: str = "127.0.0.1"
    operator_port: int = 8022
    visitor_port: int = 8023
    allow_public: bool = False

    def __post_init__(self) -> None:
        if type(self) is not EchoBindings or type(self.host) is not str:
            raise ValueError("invalid echo bindings")
        if "%" in self.host:
            raise ValueError("scoped addresses are not accepted")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            raise ValueError("bind address must be a literal IP") from None
        if type(self.allow_public) is not bool or (not self.allow_public and not address.is_loopback):
            raise ValueError("non-loopback binding requires explicit exposure permission")
        for port in (self.operator_port, self.visitor_port):
            if type(port) is not int or not 1024 <= port <= 65535:
                raise ValueError("listener ports must be unprivileged and explicit")
        if self.operator_port == self.visitor_port:
            raise ValueError("echo slots need distinct ports")

    @property
    def digest(self) -> str:
        self.__post_init__()
        representation = {"host": self.host, "operator_port": self.operator_port,
                          "visitor_port": self.visitor_port, "allow_public": self.allow_public,
                          "mode": "same_socket_mirror", "limits_per_slot": _SERVICE_LIMITS}
        return hashlib.sha256(json.dumps(representation, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def authorization_scope(bindings: EchoBindings) -> AuthorizationScope:
    if type(bindings) is not EchoBindings:
        raise ValueError("invalid echo bindings")
    return AuthorizationScope("backup_echo", bindings.digest)


async def run_backup_echo(bindings: EchoBindings, *, authorization: AuthorizationGrant | None = None,
                          scope: AuthorizationScope | None = None) -> dict[str, Any]:
    """Run two inward-only surfaces; cancellation/failed admission closes both.

    The reviewed caller must request a new grant. No process, VM, host networking,
    proxy, firewall, external endpoint or evidence file is created by this function.
    """
    expected = authorization_scope(bindings)
    if type(authorization) is not AuthorizationGrant or type(scope) is not AuthorizationScope or scope != expected:
        raise AuthorizationError("fresh exact-scope echo authorization required")
    authorization.begin(expected)
    services: list[DecoyServer] = []
    try:
        authorization.check(expected)
        if _CREDENTIAL_NAMES.intersection(os.environ):
            raise ValueError("credential-bearing environment refused")
        # Copy the validated immutable values; no input bytes can mutate configuration.
        selected = EchoBindings(bindings.host, bindings.operator_port, bindings.visitor_port, bindings.allow_public)
        throttle = InboundThrottle(**_PACING_LIMITS)
        for port in (selected.operator_port, selected.visitor_port):
            authorization.check(expected)
            service = DecoyServer(response_mode="mirror", throttle=throttle, **_SERVICE_LIMITS)
            services.append(service)
            server = await service.start(host=selected.host, port=port, allow_public=selected.allow_public)
            authorization.check(expected)
            if not server.is_serving():
                raise RuntimeError("echo startup failed closed")
        while True:
            authorization.check(expected)
            # Each server has an independent 30-second lifetime plus byte/session
            # guards. Do not restart a failed slot or leave the other slot running.
            if any(service._shutdown_requested for service in services):
                break
            if any(service.server is None or
                   (not service.server.is_serving() and service.active_sessions == 0)
                   for service in services):
                break
            await asyncio.sleep(0.05)
        authorization.check(expected)
        snapshots = [service.budget_snapshot() for service in services]
        return {"format": "bounded_backup_echo_v1", "provider": "local",
                "bindings_sha256": expected.input_ref, "slots": 2,
                "response": "same_connection_opaque_echo_only", "cross_slot_forwarding": False,
                "dial_out_performed": False, "visitor_input_executed": False,
                "vm_provisioned": False, "vm_isolation_verified": False,
                "external_routing_configured": False, "restarted": False,
                "limits_per_slot": dict(_SERVICE_LIMITS),
                "pacing": {"shared_across_slots": True, "limits": dict(_PACING_LIMITS),
                           "counters": throttle.snapshot()["counters"],
                           "denied_connections": sum(service._throttle_denials for service in services)},
                "payload_capture": False,
                "aggregate_admitted_input_bytes": sum(item["usage"]["input_bytes_total"] for item in snapshots),
                "aggregate_reserved_output_bytes": sum(item["usage"]["output_bytes_total"] for item in snapshots)}
    finally:
        # Cleanup remains mandatory even when permission has been revoked.
        try:
            for service in services:
                service._begin_shutdown("operator_shutdown")
            outcomes = await asyncio.gather(*(service.shutdown() for service in services), return_exceptions=True)
            if any(isinstance(outcome, BaseException) for outcome in outcomes):
                raise RuntimeError("echo cleanup unavailable")
        finally:
            authorization.revoke()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--operator-port", type=int, default=8022)
    parser.add_argument("--visitor-port", type=int, default=8023)
    parser.add_argument("--allow-public", action="store_true")
    parser.add_argument("--consent", action="store_true")
    grant = None
    try:
        args = parser.parse_args(argv)
        bindings = EchoBindings(args.host, args.operator_port, args.visitor_port, args.allow_public)
        scope = authorization_scope(bindings)
        grant = request_authorization(scope, consent=args.consent)
        if grant is None:
            print("Permission required; no echo port was opened.", file=sys.stderr)
            return 2
        with cancellation_guard(grant):
            result = asyncio.run(run_backup_echo(bindings, authorization=grant, scope=scope))
            print(json.dumps(result, sort_keys=True))
        return 0
    except (AuthorizationError, ValueError, OSError, RuntimeError, KeyboardInterrupt):
        print("Echo authorization or service failed; both surfaces stopped. No VM or routing was activated.", file=sys.stderr)
        return 2
    finally:
        if grant is not None:
            grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
