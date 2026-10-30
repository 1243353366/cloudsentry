"""VMBoot/physical-console components confer no runtime authority on VM profiles."""
import hashlib
import json
import unittest
from xml.etree import ElementTree as ET

from reverse_shell_decoy.backup_admission import (
    make_libvirt_candidate, make_pc_free_candidate, review_libvirt, review_pc_free,
)

SESSION = "1234567890abcdef"


def pinned(review, raw):
    return review(raw, hashlib.sha256(raw).hexdigest())


class BackupBootBoundaryTests(unittest.TestCase):
    def test_utf16_cannot_hide_a_dtd_from_the_preparse_guard(self):
        candidate = make_libvirt_candidate(SESSION)
        candidate = candidate.replace("cloudsentry-backup-" + SESSION + "</name>", "&identity;</name>")
        source = '<!DOCTYPE domain [<!ENTITY identity "cloudsentry-backup-' + SESSION + '">]>' + candidate
        for raw in (source.encode("utf-16"), source.encode("utf-16-le"), source.encode("utf-16-be")):
            report = pinned(review_libvirt, raw)
            self.assertNotEqual(report["admission_code"], "STATIC_PROFILE_ACCEPTED")
            self.assertFalse(report["ready_for_deployment"])

    def test_integer_is_not_accepted_as_a_boolean_volume_control(self):
        image = "ghcr.io/dockur/windows@sha256:" + "a" * 64
        document = json.loads(make_pc_free_candidate(image, SESSION))
        document["services"]["windows"]["volumes"][0]["volume"]["nocopy"] = 1
        report = pinned(review_pc_free, json.dumps(document).encode())
        self.assertEqual(report["admission_code"], "SCHEMA_REJECTED")
        self.assertFalse(report["ready_for_deployment"])

    def test_vmboot_kernel_initrd_firmware_and_commandline_additions_are_rejected(self):
        for tag, value in (("kernel", "/unreviewed/kernel"), ("initrd", "/unreviewed/initrd"),
                           ("loader", "/unreviewed/EDK2.fd"), ("nvram", "/unreviewed/nvram"),
                           ("cmdline", "run-unreviewed-recovery")):
            root = ET.fromstring(make_libvirt_candidate(SESSION))
            ET.SubElement(root.find("os"), tag).text = value
            report = pinned(review_libvirt, ET.tostring(root))
            with self.subTest(tag=tag):
                self.assertNotEqual(report["admission_code"], "STATIC_PROFILE_ACCEPTED")
                self.assertFalse(report["ready_for_deployment"])
                self.assertEqual(report["machine_actions"], [])

    def test_openterface_usb_video_hid_and_management_channels_are_rejected(self):
        for fragment in ('<hostdev mode="subsystem" type="usb"/>',
                         '<channel type="unix"/>', '<graphics type="vnc"/>',
                         '<filesystem type="mount"/>', '<serial type="tcp"/>',
                         '<interface type="network"/>'):
            root = ET.fromstring(make_libvirt_candidate(SESSION))
            root.find("devices").append(ET.fromstring(fragment))
            report = pinned(review_libvirt, ET.tostring(root))
            with self.subTest(fragment=fragment):
                self.assertNotEqual(report["admission_code"], "STATIC_PROFILE_ACCEPTED")
                self.assertFalse(report["ready_for_deployment"])

    def test_pc_free_boot_hooks_console_passthrough_and_docker_socket_are_rejected(self):
        image = "ghcr.io/dockur/windows@sha256:" + "a" * 64
        for change in ("firmware_command", "hid_devices", "docker_socket", "management_port"):
            document = json.loads(make_pc_free_candidate(image, SESSION))
            service = document["services"]["windows"]
            if change == "firmware_command":
                service["environment"]["COMMAND"] = "unreviewed-boot-hook"
            elif change == "hid_devices":
                service["devices"].append("/dev/bus/usb:/dev/bus/usb")
            elif change == "docker_socket":
                service["volumes"].append({"type": "bind", "source": "/var/run/docker.sock",
                                           "target": "/var/run/docker.sock"})
            else:
                service["ports"] = ["8006:8006", "3389:3389"]
            report = pinned(review_pc_free, json.dumps(document).encode())
            with self.subTest(change=change):
                self.assertNotEqual(report["admission_code"], "STATIC_PROFILE_ACCEPTED")
                self.assertFalse(report["ready_for_deployment"])
                self.assertEqual(report["machine_actions"], [])


if __name__ == "__main__":
    unittest.main()
