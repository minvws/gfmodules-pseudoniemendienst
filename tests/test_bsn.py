import unittest

from app.bsn import is_valid_bsn


class TestBSN(unittest.TestCase):
    def test_bsn(self) -> None:
        self.assertTrue(is_valid_bsn(123456782))
        self.assertTrue(is_valid_bsn("123456782"))
        self.assertTrue(is_valid_bsn("950000012"))
        self.assertTrue(is_valid_bsn(12))

        self.assertFalse(is_valid_bsn("950000013"))
        self.assertFalse(is_valid_bsn("950000011"))
        self.assertFalse(is_valid_bsn(123456781))
        self.assertFalse(is_valid_bsn("123456783"))
        self.assertFalse(is_valid_bsn("12345678"))
        self.assertFalse(is_valid_bsn("foobar"))
