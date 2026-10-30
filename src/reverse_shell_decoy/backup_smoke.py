"""Finite smoke-result validation, not VM attestation or deployment authority."""
from __future__ import annotations

_EXPECTED_LAYERS = (
    "primary_vm_configuration", "pc_free_backup_configuration",
    "two_inbound_echo_surfaces", "emergency_sink", "opaque_mirror",
)


def validate_layer_results(layers: object) -> bool:
    """Require actual executed tests in every fixed scope, with zero failures/skips."""
    if type(layers) is not list or len(layers) != len(_EXPECTED_LAYERS):
        return False
    for name, result in zip(_EXPECTED_LAYERS, layers):
        if type(result) is not dict or set(result) != {
            "layer", "tests_run", "failures", "errors", "skipped", "passed", "runtime_vm_boot_tested"}:
            return False
        if result["layer"] != name or type(result["passed"]) is not bool or result["passed"] is not True:
            return False
        if result["runtime_vm_boot_tested"] is not False:
            return False  # A local synthetic harness cannot grant this attestation.
        for key in ("tests_run", "failures", "errors", "skipped"):
            if type(result[key]) is not int:
                return False
        if not 1 <= result["tests_run"] <= 1000:
            return False
        if any(result[key] != 0 for key in ("failures", "errors", "skipped")):
            return False
    return True


def negative_control_results() -> dict[str, bool]:
    """Prove this validator rejects common falsified/incomplete smoke results."""
    baseline = [{"layer": name, "tests_run": 1, "failures": 0, "errors": 0,
                 "skipped": 0, "passed": True, "runtime_vm_boot_tested": False}
                for name in _EXPECTED_LAYERS]
    import copy
    controls = {"accepts_complete_synthetic_control": validate_layer_results(baseline)}
    for key, value in (("failures", 1), ("errors", 1), ("skipped", 1), ("tests_run", 0),
                       ("tests_run", True), ("passed", False), ("passed", "true"),
                       ("runtime_vm_boot_tested", True), ("layer", "unreviewed-backend")):
        changed = copy.deepcopy(baseline)
        changed[0][key] = value
        controls["rejects_" + key + "_" + str(value)] = not validate_layer_results(changed)
    controls["rejects_missing_layer"] = not validate_layer_results(baseline[:-1])
    controls["rejects_duplicate_layer"] = not validate_layer_results([baseline[0]] * len(baseline))
    return controls
