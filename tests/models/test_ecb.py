import pytest

import src.models.mode_ecb as mode_ecb
import src.utils.padding_schemes as padding_schemes


# Autoapplied
@pytest.fixture(autouse=True)
def _silence_info_logs(monkeypatch):
    # Keep unit tests clean: info-start logs not needed here
    monkeypatch.setattr(mode_ecb, "should_log_starts", lambda: False)
    monkeypatch.setattr(mode_ecb, "log_info", lambda msg: None)


# encrypt should return ciphertext and log success
def test_encrypt_returns_ciphertext_and_logs_success(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    pt = b"HELLO ECB"  # not block aligned, it needs padding

    ecb = mode_ecb.AESECB(key)

    ct = ecb.encrypt(pt, padding="PKCS7")

    assert isinstance(ct, bytes)
    assert len(ct) % 16 == 0

    assert error_calls == []
    assert len(success_calls) == 1
    assert "ECB encryption done" in success_calls[0]
    assert "module=mode_ecb" in success_calls[0]
    assert "func=encrypt" in success_calls[0]


# encrypt should reject non-bytes plaintext types and log exactly one error
@pytest.mark.parametrize("bad_pt", [123, None, object()])
def test_encrypt_rejects_bad_plaintext_type_and_logs_error(monkeypatch, bad_pt):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    ecb = mode_ecb.AESECB(key)

    with pytest.raises(Exception):
        ecb.encrypt(bad_pt, padding="PKCS7")  # type: ignore[arg-type]

    assert success_calls == []
    assert len(error_calls) == 1
    assert "ECB validation failed" in error_calls[0]
    assert "module=mode_ecb" in error_calls[0]
    assert "func=encrypt" in error_calls[0]
    assert "step=plaintext_type" in error_calls[0]


# encrypt should require block-aligned plaintext when padding is NONE and log an error
def test_encrypt_padding_none_requires_block_aligned_plaintext_and_logs_error(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    pt = b"A" * 15

    ecb = mode_ecb.AESECB(key)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        ecb.encrypt(pt, padding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=encrypt_raw" in error_calls[0]


# encrypt + decrypt should roundtrip correctly for all padding modes
@pytest.mark.parametrize("padding", ["PKCS7", "X923", "ISO/IEC 7816-4"])
def test_encrypt_decrypt_roundtrip_all_padding_modes(monkeypatch, padding):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x22" * 16
    pt = b"ecb-roundtrip: \x00\x01\x02 + text"

    ecb = mode_ecb.AESECB(key)

    ct = ecb.encrypt(pt, padding=padding)
    back = ecb.decrypt(ct, unpadding=padding)

    assert back == pt
    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt


# PKCS7 should add a full block when plaintext is already block-aligned (from 16 bytes total is 32 bytes ciphertext)
def test_pkcs7_adds_full_block_when_plaintext_is_block_aligned(monkeypatch):
    success_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    pt = b"A" * 16

    ecb = mode_ecb.AESECB(key)

    ct = ecb.encrypt(pt, padding="PKCS7")
    assert len(ct) == 32

    back = ecb.decrypt(ct, unpadding="PKCS7")
    assert back == pt
    assert len(success_calls) == 2


# decrypt should reject non-bytes ciphertext and log an error
def test_decrypt_rejects_wrong_ciphertext_type_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    ecb = mode_ecb.AESECB(key)

    with pytest.raises(TypeError, match=r"ciphertext must be bytes"):
        ecb.decrypt("not-bytes", unpadding="NONE")  # type: ignore[arg-type]

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=ciphertext_type" in error_calls[0]


# decrypt should reject non-block-aligned ciphertext and log an error
def test_decrypt_rejects_non_block_aligned_ciphertext_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    ecb = mode_ecb.AESECB(key)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        ecb.decrypt(b"A" * 15, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=decrypt_raw" in error_calls[0]


# decrypt should raise ValueError for unpadding mismatch
def test_decrypt_unpadding_error_is_raised_without_double_logging(monkeypatch):
    mode_error_calls: list[str] = []
    pad_error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: mode_error_calls.append(msg))
    monkeypatch.setattr(padding_schemes, "log_error", lambda msg: pad_error_calls.append(msg))

    key = b"\x00" * 16

    # Length=14 then PKCS7 pad bytes = 0x02 0x02
    # If we decrypt with X923 unpadding it must fail deterministically (expects 0x00 0x02)
    pt = b"A" * 14

    ecb = mode_ecb.AESECB(key)

    ct = ecb.encrypt(pt, padding="PKCS7")

    with pytest.raises(ValueError, match=r"Unpadding failed"):
        ecb.decrypt(ct, unpadding="X923")

    # padding_schemes should log the root cause
    assert len(pad_error_calls) >= 1

    # mode_ecb must not log again for the PaddingError
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
#   - SP 800-38A (Appendix F): ECB mode encryption/decryption examples. Link: https://dx.doi.org/10.6028/NIST.SP.800-38A
#
# Purpose:
#   These vectors allow us to assert that our ECB implementation produces identical results to the official NIST defined outputs.
#   If these tests pass, we know our ECB logic is compliant with the standard.
#
# NB:
#  padding and unpadding must be NONE here because NIST vectors are raw block-aligned messages.
# -----------------------------------------------------------------------------

# ECB: SP 800-38A Appendix F.1.1 (ECB-AES128.Encrypt)
# PDF page 24
def test_encrypt_decrypt_matches_nist_sp800_38a_vector(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ecb, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ecb, "log_error", lambda msg: error_calls.append(msg))

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    expected_ct = bytes.fromhex(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"
    )

    ecb = mode_ecb.AESECB(key)

    ct = ecb.encrypt(pt, padding="NONE")
    assert ct == expected_ct

    back = ecb.decrypt(ct, unpadding="NONE")
    assert back == pt

    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt
