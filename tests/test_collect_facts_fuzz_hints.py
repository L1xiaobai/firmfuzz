import importlib.util
import os
import stat
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "collectFacts.py")


def load_module():
    spec = importlib.util.spec_from_file_location("collectFacts", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CollectFactsFuzzHintsTest(unittest.TestCase):
    def test_gather_fuzz_hints_discovers_web_roots_and_entrypoints(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, "www", "cgi-bin"))
            os.makedirs(os.path.join(rootfs, "etc"))
            index = os.path.join(rootfs, "www", "index.html")
            cgi = os.path.join(rootfs, "www", "cgi-bin", "apply.cgi")
            soap = os.path.join(rootfs, "www", "HNAP1.xml")
            auth = os.path.join(rootfs, "www", "login.asp")
            conf = os.path.join(rootfs, "etc", "httpd.conf")
            for path, data in [
                (index, "<form action='/cgi-bin/apply.cgi'></form>"),
                (cgi, "#!/bin/sh\n"),
                (soap, "<soap>HNAP</soap>"),
                (auth, "password login auth"),
                (conf, "Listen 8080\nDocumentRoot /www\n"),
            ]:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
            os.chmod(cgi, os.stat(cgi).st_mode | stat.S_IXUSR)

            hints = mod.gather_fuzz_hints(rootfs)

        self.assertEqual(hints["web_roots"], ["/www"])
        self.assertIn("/www/cgi-bin/apply.cgi", hints["web_entrypoints"])
        self.assertIn("/www/HNAP1.xml", hints["api_entrypoints"])
        self.assertIn("/www/login.asp", hints["auth_hints"])
        self.assertIn("/etc/httpd.conf", hints["config_files"])


if __name__ == "__main__":
    unittest.main()
