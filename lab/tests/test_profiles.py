#!/usr/bin/env python3
import importlib.util, json, pathlib, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("profile", ROOT / "scripts/profile.py")
profile = importlib.util.module_from_spec(spec); spec.loader.exec_module(profile)

class ProfilesTest(unittest.TestCase):
    def test_p0_matrix_is_valid_and_covers_required_axes(self):
        rows = [profile.load(path) for path in sorted((ROOT / "profiles").glob("*.yaml"))]
        self.assertGreaterEqual(len(rows), 6)
        self.assertEqual({"tunnel", "transport"}, {row["mode"] for row in rows})
        self.assertEqual({"ipv4", "ipv6"}, {row["address_family"] for row in rows})
        self.assertTrue(any(row["pfs"] for row in rows)); self.assertTrue(any(not row["pfs"] for row in rows))
        self.assertTrue(any("aes128" in row["esp"] for row in rows)); self.assertTrue(any("aes256" in row["esp"] for row in rows))
        self.assertTrue(any("gcm" in row["esp"] for row in rows)); self.assertTrue(any("sha256" in row["esp"] for row in rows))
        self.assertEqual({"modp2048", "ecp256"}, {row["dh_group"] for row in rows})

if __name__ == "__main__": unittest.main()
