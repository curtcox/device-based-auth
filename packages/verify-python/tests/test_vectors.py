"""Every conformance vector in spec/vectors/, checked exactly as spec/vectors.test.js does for JS."""
import unittest

try:
    from . import support
except ImportError:  # run with the tests directory as the top level
    import support

from devicebasedauth_verify import (VerificationError, decode_status_list, evaluate_grants, get_bit, verify_credential,
                                    verify_jws, verify_proof)

EVALUATION = support.load_vectors("evaluation.json")
CREDENTIALS = support.load_vectors("credentials.json")


def outcome(fn):
    try:
        fn()
        return {"valid": True}
    except VerificationError as error:
        return {"valid": False, "code": error.code}


class EvaluationVectors(unittest.TestCase):
    def test_vectors_present(self):
        self.assertGreaterEqual(len(EVALUATION["cases"]), 40)

    def test_every_case(self):
        for case in EVALUATION["cases"]:
            with self.subTest(case["name"]):
                result = evaluate_grants(case["grants"], case["context"])
                self.assertEqual({"allow": result["allow"], "grant_index": result["grant_index"], "reasons": result["reasons"]}, case["expected"])


class CredentialVectors(unittest.TestCase):
    def test_credentials(self):
        self.assertTrue(CREDENTIALS["credentials"])
        for case in CREDENTIALS["credentials"]:
            with self.subTest(case["name"]):
                result = outcome(lambda: verify_credential(case["jws"], jwks=CREDENTIALS["jwks"], issuer=CREDENTIALS["issuer"],
                                                           audience=case.get("audience"), now=case["now"]))
                self.assertEqual(result, case["expected"])

    def test_proofs(self):
        self.assertTrue(CREDENTIALS["proofs"])
        for case in CREDENTIALS["proofs"]:
            with self.subTest(case["name"]):
                result = outcome(lambda: verify_proof(case["proof"], method=case["method"], url=case["url"], credential=case.get("credential"),
                                                      jkt=case.get("jkt"), now=case.get("now"), nonce=case.get("nonce")))
                self.assertEqual(result, case["expected"])

    def test_status_list(self):
        decoded = verify_jws(CREDENTIALS["status_list"]["jwt"], CREDENTIALS["jwks"]["keys"][0])
        self.assertIsNotNone(decoded)
        data = decode_status_list(decoded["payload"]["status_list"])
        self.assertEqual([i for i in range(9) if get_bit(data, i)], CREDENTIALS["status_list"]["revoked_indexes"])


if __name__ == "__main__":
    unittest.main()
