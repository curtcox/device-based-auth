"""Every conformance vector in spec/vectors/, checked exactly as spec/vectors.test.js does for JS."""
import unittest

try:
    from . import support
except ImportError:  # run with the tests directory as the top level
    import support

from devicebasedauth_verify import (VerificationError, decode_jws, decode_status_list, evaluate_grants, get_bit,
                                    verify_confirmation, verify_credential, verify_jws, verify_proof)

EVALUATION = support.load_vectors("evaluation.json")
CREDENTIALS = support.load_vectors("credentials.json")


def outcome(fn):
    try:
        fn()
        return {"valid": True}
    except VerificationError as error:
        return {"valid": False, "code": error.code}


def _slug(name):
    return "".join(c if c.isalnum() else "_" for c in name.lower()).strip("_")


class EvaluationVectors(unittest.TestCase):
    """One test per case in evaluation.json: allow, grant_index and per-grant reasons must match."""

    def test_vectors_present(self):
        self.assertGreaterEqual(len(EVALUATION["cases"]), 40)


class CredentialVectors(unittest.TestCase):
    """One test per credential and proof in credentials.json, plus the status list."""

    def test_status_list(self):
        decoded = verify_jws(CREDENTIALS["status_list"]["jwt"], CREDENTIALS["jwks"]["keys"][0])
        self.assertIsNotNone(decoded)
        data = decode_status_list(decoded["payload"]["status_list"])
        self.assertEqual([i for i in range(9) if get_bit(data, i)], CREDENTIALS["status_list"]["revoked_indexes"])


def _evaluation_test(case):
    def test(self):
        result = evaluate_grants(case["grants"], case["context"])
        self.assertEqual({"allow": result["allow"], "grant_index": result["grant_index"], "reasons": result["reasons"]}, case["expected"])
    return test


def _credential_test(case):
    def test(self):
        result = outcome(lambda: verify_credential(case["jws"], jwks=CREDENTIALS["jwks"], issuer=CREDENTIALS["issuer"],
                                                   audience=case.get("audience"), now=case["now"]))
        self.assertEqual(result, case["expected"])
    return test


def _proof_test(case):
    def test(self):
        result = outcome(lambda: verify_proof(case["proof"], method=case["method"], url=case["url"], credential=case.get("credential"),
                                              jkt=case.get("jkt"), now=case.get("now"), nonce=case.get("nonce")))
        self.assertEqual(result, case["expected"])
    return test


def _confirmation_test(case):
    credential = decode_jws(next(c for c in CREDENTIALS["credentials"] if c["name"] == "valid credential")["jws"])["payload"]

    def test(self):
        result = outcome(lambda: verify_confirmation(case["jws"], jwks=CREDENTIALS["jwks"], issuer=CREDENTIALS["issuer"],
                                                     credential=credential, audience=case.get("audience")))
        self.assertEqual(result, case["expected"])
    return test


for _i, _case in enumerate(EVALUATION["cases"]):
    setattr(EvaluationVectors, f"test_{_i:03d}_{_slug(_case['name'])}", _evaluation_test(_case))
for _i, _case in enumerate(CREDENTIALS["credentials"]):
    setattr(CredentialVectors, f"test_credential_{_i:02d}_{_slug(_case['name'])}", _credential_test(_case))
for _i, _case in enumerate(CREDENTIALS["confirmations"]):
    setattr(CredentialVectors, f"test_confirmation_{_i:02d}_{_slug(_case['name'])}", _confirmation_test(_case))
for _i, _case in enumerate(CREDENTIALS["proofs"]):
    setattr(CredentialVectors, f"test_proof_{_i:02d}_{_slug(_case['name'])}", _proof_test(_case))


if __name__ == "__main__":
    unittest.main()


class JavaScriptCrosscheck(unittest.TestCase):
    """Edge cases beyond spec/vectors, decided by the JavaScript reference (shared with the Go port)."""

    def test_crosscheck_cases(self):
        import json
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[2] / "verify-go" / "testdata" / "crosscheck.json"
        cases = json.loads(path.read_text())["cases"]
        self.assertGreater(len(cases), 0)
        for case in cases:
            with self.subTest(case["name"]):
                result = evaluate_grants(case["grants"], case["context"])
                got = {k: result.get(k) for k in ("allow", "grant_index", "reasons", "online_required")}
                self.assertEqual(got, {k: case["result"].get(k) for k in got})
