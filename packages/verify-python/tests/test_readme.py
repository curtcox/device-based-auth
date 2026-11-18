"""The README's examples are executed here: this repository never ships an untested sample."""
import doctest
import os
import re
import time
import unittest
from unittest import mock

try:
    from . import support
except ImportError:
    import support

import devicebasedauth_verify.verifier as verifier_module

with open(os.path.join(support.PACKAGE_ROOT, "README.md"), encoding="utf-8") as _handle:
    BLOCKS = re.findall(r"```python\n(.*?)```", _handle.read(), re.DOTALL)


class ReadmeTest(unittest.TestCase):
    def test_readme_has_both_examples(self):
        self.assertEqual(len(BLOCKS), 2)

    def test_verify_request_example(self):
        issuer = support.FakeIssuer(lambda: int(time.time()))
        source = next(b for b in BLOCKS if ">>>" not in b)
        namespace = {}
        # The example uses the default (urllib) fetch; route it to the in-memory issuer instead.
        with mock.patch.object(verifier_module, "default_fetch", issuer.fetch):
            exec(compile(source, "README.md", "exec"), namespace)
            url = "https://hashbin.org/api/content?draft=1"
            status, body = namespace["handle"]("POST", url, issuer.headers("POST", url))
            self.assertEqual(status, 200, body)
            self.assertEqual(body, {"account": "acct_test", "device": "dev_TESTDEVICE01", "caveats": {}})
            status, body = namespace["handle"]("POST", url, {})
            self.assertEqual((status, body["error"]), (401, "credential_required"))
        self.assertGreater(issuer.count("https://devicebasedauth.org/.well-known/jwks.json"), 0)

    def test_evaluate_grants_example(self):
        source = next(b for b in BLOCKS if ">>>" in b)
        test = doctest.DocTestParser().get_doctest(source, {}, "README", "README.md", 0)
        runner = doctest.DocTestRunner(optionflags=doctest.NORMALIZE_WHITESPACE)
        runner.run(test)
        summary = runner.summarize(verbose=False)
        self.assertEqual((summary.failed, summary.attempted > 3), (0, True))


if __name__ == "__main__":
    unittest.main()
