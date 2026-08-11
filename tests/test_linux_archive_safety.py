from __future__ import annotations

import gzip
import io
import lzma
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LINUX_TOOLS = PROJECT_ROOT / "packaging" / "linux"
sys.path.insert(0, str(LINUX_TOOLS))

import release_common as common  # noqa: E402


def raw_tar_member(
    name: str,
    data: bytes,
    *,
    typeflag: bytes = tarfile.REGTYPE,
    linkname: str = "",
    mode: int = 0o444,
) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = typeflag
    info.linkname = linkname
    info.mode = mode
    info.size = len(data)
    header = info.tobuf(format=tarfile.USTAR_FORMAT)
    padding = b"\0" * ((-len(data)) % common.TAR_BLOCK_BYTES)
    return header + data + padding


def raw_tar(*members: bytes) -> bytes:
    return b"".join(members) + b"\0" * (2 * common.TAR_BLOCK_BYTES)


def pax_record(key: str, value: str) -> bytes:
    payload = f"{key}={value}\n".encode("utf-8")
    length = len(payload) + 2
    while True:
        encoded = f"{length} ".encode("ascii") + payload
        if len(encoded) == length:
            return encoded
        length = len(encoded)


class LinuxArchiveSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.limits = common.ArchiveLimits(
            max_members=8,
            max_file_bytes=4096,
            max_total_bytes=16 * 1024,
            max_path_bytes=128,
        )

    def test_tar_caps_cover_raw_expansion_headers_extensions_and_padding(self) -> None:
        tiny = common.ArchiveLimits(1, 1024, 1024, 64)
        raw_cap, expanded_cap, _headers, extension_cap = common._tar_stream_caps(tiny)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            raw_bomb = root / "raw-bomb"
            raw_bomb.write_bytes(b"\0" * (raw_cap + 1))
            with self.assertRaisesRegex(common.ReleaseError, "raw tar stream"):
                common.inspect_tar(raw_bomb, limits=tiny)

            expanded_bomb = root / "expanded-bomb"
            expanded_bomb.write_bytes(gzip.compress(b"\0" * (expanded_cap + 1)))
            with self.assertRaisesRegex(common.ReleaseError, "expanded tar stream"):
                common.inspect_tar(expanded_bomb, limits=tiny)

            metadata_bomb = root / "metadata-bomb"
            metadata_bomb.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "PaxHeader",
                        b"x" * (extension_cap + 1),
                        typeflag=tarfile.XHDTYPE,
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "extension metadata"):
                common.inspect_tar(metadata_bomb, limits=tiny)

            too_many_extensions = root / "many-extensions"
            record = pax_record("comment", "bounded")
            too_many_extensions.write_bytes(
                raw_tar(
                    *(
                        raw_tar_member(
                            f"PaxHeader{index}", record, typeflag=tarfile.XGLTYPE
                        )
                        for index in range(11)
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "extension record count"):
                common.inspect_tar(too_many_extensions, limits=tiny)

            too_many_headers = root / "many-headers"
            too_many_headers.write_bytes(
                raw_tar(
                    *(
                        raw_tar_member(
                            f"Global{index}", record, typeflag=tarfile.XGLTYPE
                        )
                        for index in range(10)
                    ),
                    raw_tar_member("root/file", b"x"),
                    raw_tar_member("FinalGlobal", record, typeflag=tarfile.XGLTYPE),
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "physical header count"):
                common.inspect_tar(too_many_headers, limits=tiny)

            bad_padding = root / "bad-padding"
            member = bytearray(raw_tar_member("root/file", b"x"))
            member[-1] = 1
            bad_padding.write_bytes(raw_tar(bytes(member)))
            with self.assertRaisesRegex(common.ReleaseError, "non-zero tar member padding"):
                common.inspect_tar(bad_padding, limits=tiny)

    def test_non_file_bodies_and_pax_size_overrides_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symlink_body = root / "symlink-body.tar"
            symlink_body.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "root/link",
                        b"x",
                        typeflag=tarfile.SYMTYPE,
                        linkname="target",
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "non-file tar member"):
                common.inspect_tar(symlink_body, limits=self.limits)

            pax_size = root / "pax-size.tar"
            pax_size.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "PaxHeader",
                        pax_record("size", "1"),
                        typeflag=tarfile.XHDTYPE,
                    ),
                    raw_tar_member("root/file", b"x"),
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "size overrides"):
                common.inspect_tar(pax_size, limits=self.limits)

            truncated = root / "truncated.tar"
            full = raw_tar(raw_tar_member("root/file", b"content"))
            truncated.write_bytes(full[:-common.TAR_BLOCK_BYTES])
            with self.assertRaisesRegex(common.ReleaseError, "end marker"):
                common.inspect_tar(truncated, limits=self.limits)

    def test_combined_prefix_collisions_fail_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = {
                "case-prefix": raw_tar(
                    raw_tar_member("root/A/one", b"1"),
                    raw_tar_member("root/a/two", b"2"),
                ),
                "file-parent": raw_tar(
                    raw_tar_member("root/parent", b"file"),
                    raw_tar_member("root/parent/child", b"child"),
                ),
                "symlink-parent": raw_tar(
                    raw_tar_member(
                        "root/link", b"", typeflag=tarfile.SYMTYPE, linkname="target"
                    ),
                    raw_tar_member("root/link/child", b"child"),
                ),
            }
            for name, data in cases.items():
                with self.subTest(name=name):
                    archive = root / name
                    archive.write_bytes(data)
                    with self.assertRaisesRegex(
                        common.ReleaseError, "colliding|descends through"
                    ):
                        common.inspect_tar(archive, limits=self.limits)

    def test_symlink_chain_extraction_is_member_order_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            archive = temporary_root / "chain.tar"
            archive.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "root/a", b"", typeflag=tarfile.SYMTYPE, linkname="b"
                    ),
                    raw_tar_member(
                        "root/b", b"", typeflag=tarfile.SYMTYPE, linkname="target"
                    ),
                    raw_tar_member("root/target", b"resolved"),
                )
            )
            members = common.inspect_tar(
                archive, limits=self.limits, expected_top="root"
            )
            extracted = common.extract_validated_tar(
                archive, temporary_root / "fresh", members=members
            )
            self.assertEqual((extracted / "a").read_bytes(), b"resolved")
            self.assertEqual((extracted / "b").read_bytes(), b"resolved")

    def test_exact_normalized_file_modes_bind_executable_inventory(self) -> None:
        members = [
            common.ArchiveMember("root", "directory", 0, 0o555),
            common.ArchiveMember("root/data", "file", 1, 0o444),
            common.ArchiveMember("root/tool", "file", 1, 0o555),
            common.ArchiveMember("root/link", "symlink", 0, 0o777, "tool"),
        ]
        common.verify_sealed_archive_modes(
            members, executable_paths={"root/tool"}
        )
        with self.assertRaisesRegex(common.ReleaseError, "exactly normalized"):
            common.verify_sealed_archive_modes(
                members, executable_paths={"root/data"}
            )
        with self.assertRaisesRegex(common.ReleaseError, "names non-files"):
            common.verify_sealed_archive_modes(
                members, executable_paths={"root/missing"}
            )

    def test_magic_inventory_is_suffix_independent_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tar_gzip = root / "opaque.bin"
            with tarfile.open(tar_gzip, "w:gz") as archive:
                data = b"source"
                info = tarfile.TarInfo("source/file")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            self.assertEqual(common.detect_archive_format(tar_gzip), "tar")

            tar_xz = root / "also-opaque"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as archive:
                data = b"xz"
                info = tarfile.TarInfo("source/xz")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            tar_xz.write_bytes(lzma.compress(raw.getvalue()))
            self.assertEqual(common.detect_archive_format(tar_xz), "tar")

            wheel_like = root / "wheel.disguised"
            with zipfile.ZipFile(wheel_like, "w") as archive:
                archive.writestr("package/module.py", b"pass\n")
            self.assertEqual(common.detect_archive_format(wheel_like), "zip")

            declared = {"also-opaque": "tar", "opaque.bin": "tar", "wheel.disguised": "zip"}
            self.assertEqual(
                common.verify_declared_archive_inventory(root, declared), declared
            )
            with self.assertRaisesRegex(common.ReleaseError, "undeclared"):
                common.verify_declared_archive_inventory(root, {})
            with self.assertRaisesRegex(common.ReleaseError, "format mismatch"):
                common.verify_declared_archive_inventory(
                    root,
                    {**declared, "opaque.bin": "gzip"},
                )

            unsupported_root = root / "unsupported"
            unsupported_root.mkdir()
            (unsupported_root / "innocent.txt").write_bytes(
                b"7z\xbc\xaf\x27\x1c" + b"\0" * 32
            )
            with self.assertRaisesRegex(common.ReleaseError, "recognized unsupported"):
                common.verify_declared_archive_inventory(unsupported_root, {})

            plain_gzip = root / "plain.tar"
            plain_gzip.write_bytes(gzip.compress(b"not a tar archive"))
            self.assertEqual(common.detect_archive_format(plain_gzip), "gzip")
            with self.assertRaisesRegex(common.ReleaseError, "format mismatch"):
                common.inspect_nested(plain_gzip, "tar", limits=self.limits)

    def test_zip_raw_stream_and_exact_end_record_are_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "safe.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("root/file", b"payload")
            details = common.inspect_zip(archive, limits=self.limits)
            self.assertEqual(details["raw_bytes"], archive.stat().st_size)
            trailing = root / "trailing.zip"
            trailing.write_bytes(archive.read_bytes() + b"unreferenced")
            with self.assertRaisesRegex(
                common.ReleaseError, "end record|unreferenced|contract"
            ):
                common.inspect_zip(trailing, limits=self.limits)
            prefixed = root / "prefixed.zip"
            prefixed.write_bytes(b"PK\x03\x04" + b"HIDDEN" * 100 + archive.read_bytes())
            with self.assertRaisesRegex(
                common.ReleaseError, "prepended|gapped|overlapping|contract"
            ):
                common.inspect_zip(prefixed, limits=self.limits)
            ancestor = root / "ancestor.zip"
            with zipfile.ZipFile(ancestor, "w") as output:
                output.writestr("root/parent", b"file")
                output.writestr("root/parent/child", b"child")
            with self.assertRaisesRegex(common.ReleaseError, "descends through"):
                common.inspect_zip(ancestor, limits=self.limits)
            tiny = common.ArchiveLimits(8, 4096, archive.stat().st_size - 1, 128)
            with self.assertRaisesRegex(common.ReleaseError, "raw zip stream"):
                common.inspect_zip(archive, limits=tiny)


if __name__ == "__main__":
    unittest.main()
