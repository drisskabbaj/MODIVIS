import pytest

import src.models.mode_cbc as mode_cbc
import src.utils.padding_schemes as padding_schemes


# Autoapplied
@pytest.fixture(autouse=True)
def _silence_info_logs(monkeypatch):
    # Keep unit tests clean: info-start logs not needed here
    monkeypatch.setattr(mode_cbc, "should_log_starts", lambda: False)
    monkeypatch.setattr(mode_cbc, "log_info", lambda msg: None)


# encrypt_with_iv should return ciphertext and iv and log success
def test_encrypt_with_iv_returns_ciphertext_and_iv_and_logs_success(monkeypatch):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    pt = b"HELLO CBC"  # not block aligned, it needs padding

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding="PKCS7")

    assert isinstance(ct, bytes)
    assert isinstance(out_iv, bytes)
    assert out_iv == iv
    assert len(ct) % 16 == 0

    assert error_calls == []
    assert warning_calls == []
    assert len(success_calls) == 1
    assert "CBC encryption" in success_calls[0]
    assert "module=mode_cbc" in success_calls[0]
    assert "func=encrypt_with_iv" in success_calls[0]


# encrypt_with_iv should generate IV when missing and log a warning
def test_encrypt_with_iv_generates_iv_when_missing_and_logs_warning(monkeypatch):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    fixed_iv = b"\x11" * 16

    def _fake_generate_random_iv(*args, **kwargs):
        return fixed_iv

    monkeypatch.setattr(mode_cbc, "generate_random_iv", _fake_generate_random_iv)

    key = b"\x00" * 16
    pt = b"abc"

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=None, padding="PKCS7")

    assert out_iv == fixed_iv
    assert len(ct) % 16 == 0

    assert error_calls == []
    assert len(warning_calls) == 1
    assert "module=mode_cbc" in warning_calls[0]
    assert "func=encrypt_with_iv" in warning_calls[0]
    assert "iv=missing" in warning_calls[0]
    assert len(success_calls) == 1


# encrypt_with_iv should reject invalid iv values and log exactly one error
@pytest.mark.parametrize("bad_iv", [b"", b"\x00" * 15, b"\x00" * 17, "00" * 16, 123])
def test_encrypt_with_iv_rejects_bad_iv_and_logs_error(monkeypatch, bad_iv):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = bad_iv
    pt = b"A" * 16

    cbc = mode_cbc.AESCBC(key)

    with pytest.raises(Exception):
        cbc.encrypt_with_iv(pt, iv=iv, padding="NONE")

    assert success_calls == []
    assert warning_calls == []
    assert len(error_calls) == 1
    assert "CBC encrypt_raw failed" in error_calls[0]
    assert "module=mode_cbc" in error_calls[0]
    assert "func=encrypt_with_iv" in error_calls[0]
    assert "step=encrypt_raw" in error_calls[0]

# encrypt_with_iv should require block-aligned plaintext when padding="NONE" and log an error
def test_encrypt_with_iv_padding_none_requires_block_aligned_plaintext_and_logs_error(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    pt = b"A" * 15

    cbc = mode_cbc.AESCBC(key)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        cbc.encrypt_with_iv(pt, iv=iv, padding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=encrypt_raw" in error_calls[0]


# encrypt_with_iv + decrypt should roundtrip correctly for all padding modes
@pytest.mark.parametrize("padding", ["PKCS7", "X923", "ISO/IEC 7816-4"])
def test_encrypt_decrypt_roundtrip_all_padding_modes(monkeypatch, padding):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x22" * 16
    iv = b"\x33" * 16
    pt = b"cbc-roundtrip: \x00\x01\x02 + text"

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding=padding)
    back = cbc.decrypt(ct, iv=out_iv, unpadding=padding)

    assert back == pt
    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt


# PKCS7 should add a full block when plaintext is already block-aligned (from 16 bytes total is 32 bytes ciphertext)
def test_pkcs7_adds_full_block_when_plaintext_is_block_aligned(monkeypatch):
    success_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    pt = b"A" * 16

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding="PKCS7")
    assert out_iv == iv
    assert len(ct) == 32

    back = cbc.decrypt(ct, iv=iv, unpadding="PKCS7")
    assert back == pt
    assert len(success_calls) == 2


# decrypt should require iv and log an error for missing iv
def test_decrypt_requires_iv_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    cbc = mode_cbc.AESCBC(key)

    with pytest.raises(ValueError, match=r"requires the same IV"):
        cbc.decrypt(b"\x00" * 16, iv=None, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=iv" in error_calls[0]
    assert "missing_iv" in error_calls[0]


# decrypt should reject non-bytes ciphertext and log an error
def test_decrypt_rejects_wrong_ciphertext_type_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    cbc = mode_cbc.AESCBC(key)

    with pytest.raises(TypeError, match=r"ciphertext must be bytes"):
        cbc.decrypt("not-bytes", iv=iv, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=ciphertext_type" in error_calls[0]


# decrypt should reject non-block-aligned ciphertext and log an error
def test_decrypt_rejects_non_block_aligned_ciphertext_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    cbc = mode_cbc.AESCBC(key)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        cbc.decrypt(b"A" * 15, iv=iv, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=decrypt_raw" in error_calls[0]


# decrypt should raise ValueError for unpadding mismatch
def test_decrypt_unpadding_error_is_raised_without_double_logging(monkeypatch):
    mode_error_calls: list[str] = []
    pad_error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: mode_error_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: pad_error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16

    # Length=14 then PKCS7 pad bytes = 0x02 0x02
    # If we decrypt with X923 unpadding it must fail deterministically (expects 0x00 0x02)
    pt = b"A" * 14

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding="PKCS7")

    with pytest.raises(ValueError, match=r"Unpadding failed"):
        cbc.decrypt(ct, iv=out_iv, unpadding="X923")

    # padding_schemes should log the root cause
    assert len(pad_error_calls) >= 1

    # mode_cbc must not log again for the PaddingError
    assert mode_error_calls == []


# -----------------------------------------------------------------------------
# Official AES reference test vectors from NIST publications
#
# NIST (U.S.) = National Institute of Standards and Technology
#
# They publish the canonical AES specification and example ciphertext outputs
# (known as test vectors) used to verify correct AES implementations.
#
# In the tests below, used are:
#   - SP 800-38A (Appendix F): ECB, CBC, and CTR mode encryption/decryption examples. Link: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#   - AESAVS (AES Algorithm Validation Suite): KAT/MMT sample datasets. Link: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
#
# Purpose:
#   These vectors allow us to assert that our AESCore implementation produces identical results to the official NIST defined outputs.
#   If these tests pass, we know our raw AES logic is compliant with the standard.
#
# NB:
#  padding/unpadding="NONE" here because NIST vectors are raw block-aligned messages.
# -----------------------------------------------------------------------------


# CBC: SP 800-38A Appendix F.2.1 (CBC-AES128.Encrypt)
# PDF page 27
def test_encrypt_decrypt_matches_nist_sp800_38a_vector(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    expected_ct = bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding="NONE")
    assert out_iv == iv
    assert ct == expected_ct

    back = cbc.decrypt(ct, iv=iv, unpadding="NONE")
    assert back == pt

    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt


# AESAVS (6.3 - The Multi-block Message Test) sample dataset
# PDF page 6
def test_encrypt_decrypt_matches_nist_aesavs_mmt_sample_dataset(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_cbc, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_cbc, "log_error", lambda msg: error_calls.append(msg))

    key = bytes.fromhex("4278b840fb44aaa757c1bf04acbe1a3e")
    iv = bytes.fromhex("57f02a5c5339daeb0a2908a06ac6393f")
    pt = bytes.fromhex(
        "3c888bbbb1a8eb9f3e9b87acaad986c4"
        "66e2f7071c83083b8a557971918850e5"
    )
    expected_ct = bytes.fromhex(
        "479c89ec14bc98994e62b2c705b5014e"
        "175bd7832e7e60a1e92aac568a861eb7"
    )

    cbc = mode_cbc.AESCBC(key)

    ct, out_iv = cbc.encrypt_with_iv(pt, iv=iv, padding="NONE")
    assert out_iv == iv
    assert ct == expected_ct

    back = cbc.decrypt(ct, iv=iv, unpadding="NONE")
    assert back == pt

    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt
