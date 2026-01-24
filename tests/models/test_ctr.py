import pytest

import src.models.mode_ctr as mode_ctr


# Autoapplied
@pytest.fixture(autouse=True)
def _silence_info_logs(monkeypatch):
    # Keep unit tests clean: info-start logs not needed here
    monkeypatch.setattr(mode_ctr, "should_log_starts", lambda: False)
    monkeypatch.setattr(mode_ctr, "log_info", lambda msg: None)


# encrypt_with_iv should return ciphertext and iv and log success
def test_encrypt_with_iv_returns_ciphertext_and_iv_and_logs_success(monkeypatch):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    pt = b"HELLO CTR"  # not block aligned, CTR does not need padding

    ctr = mode_ctr.AESCTR(key)

    ct, out_iv = ctr.encrypt_with_iv(pt, iv=iv, padding="NONE")

    assert isinstance(ct, bytes)
    assert isinstance(out_iv, bytes)
    assert out_iv == iv
    assert len(ct) == len(pt)

    assert error_calls == []
    assert warning_calls == []
    assert len(success_calls) == 1
    assert "CTR encryption done" in success_calls[0]
    assert "module=mode_ctr" in success_calls[0]
    assert "func=encrypt_with_iv" in success_calls[0]


# encrypt_with_iv should generate IV when missing and log a warning
def test_encrypt_with_iv_generates_iv_when_missing_and_logs_warning(monkeypatch):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    fixed_iv = b"\x11" * 16

    def _fake_generate_random_iv(*args, **kwargs):
        return fixed_iv

    monkeypatch.setattr(mode_ctr, "generate_random_iv", _fake_generate_random_iv)

    key = b"\x00" * 16
    pt = b"abc"

    ctr = mode_ctr.AESCTR(key)

    ct, out_iv = ctr.encrypt_with_iv(pt, iv=None, padding="NONE")

    assert out_iv == fixed_iv
    assert len(ct) == len(pt)

    assert error_calls == []
    assert len(warning_calls) == 1
    assert "module=mode_ctr" in warning_calls[0]
    assert "func=encrypt_with_iv" in warning_calls[0]
    assert "iv=missing" in warning_calls[0]
    assert len(success_calls) == 1


# encrypt_with_iv should reject padding that is not NONE and log exactly one error
@pytest.mark.parametrize("bad_padding", ["PKCS7", "X923", "ISO/IEC 7816-4"])
def test_encrypt_with_iv_rejects_padding_and_logs_error(monkeypatch, bad_padding):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    pt = b"CTR"

    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(ValueError, match=r"Padding"):
        ctr.encrypt_with_iv(pt, iv=iv, padding=bad_padding)

    assert success_calls == []
    assert len(error_calls) == 1
    assert "CTR validation failed" in error_calls[0]
    assert "module=mode_ctr" in error_calls[0]
    assert "func=encrypt_with_iv" in error_calls[0]
    assert "step=padding" in error_calls[0]


# encrypt_with_iv should reject invalid iv values and log exactly one error
@pytest.mark.parametrize("bad_iv", [b"", b"\x00" * 15, b"\x00" * 17, "00" * 16, 123])
def test_encrypt_with_iv_rejects_bad_iv_and_logs_error(monkeypatch, bad_iv):
    success_calls: list[str] = []
    warning_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_warning", lambda msg: warning_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    pt = b"A" * 17

    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(Exception):
        ctr.encrypt_with_iv(pt, iv=bad_iv, padding="NONE")

    assert success_calls == []
    assert warning_calls == []
    assert len(error_calls) == 1
    assert "CTR encrypt_raw failed" in error_calls[0]
    assert "module=mode_ctr" in error_calls[0]
    assert "func=encrypt_with_iv" in error_calls[0]
    assert "step=encrypt_raw" in error_calls[0]


# encrypt_with_iv + decrypt should roundtrip correctly for different plaintext lengths
@pytest.mark.parametrize("pt", [b"", b"A", b"A" * 15, b"A" * 16, b"A" * 17, b"ctr-roundtrip: \x00\x01\x02 + text"])
def test_encrypt_decrypt_roundtrip_various_lengths(monkeypatch, pt):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x22" * 16
    iv = b"\x33" * 16

    ctr = mode_ctr.AESCTR(key)

    ct, out_iv = ctr.encrypt_with_iv(pt, iv=iv, padding="NONE")
    back = ctr.decrypt(ct, iv=out_iv, unpadding="NONE")

    assert back == pt
    assert len(ct) == len(pt)
    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt


# decrypt should reject unpadding that is not NONE and log exactly one error
@pytest.mark.parametrize("bad_unpadding", ["PKCS7", "X923", "ISO/IEC 7816-4"])
def test_decrypt_rejects_unpadding_and_logs_error(monkeypatch, bad_unpadding):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(ValueError, match=r"Unpadding"):
        ctr.decrypt(b"\x00", iv=iv, unpadding=bad_unpadding)

    assert success_calls == []
    assert len(error_calls) == 1
    assert "CTR validation failed" in error_calls[0]
    assert "module=mode_ctr" in error_calls[0]
    assert "func=decrypt" in error_calls[0]
    assert "step=unpadding" in error_calls[0]


# decrypt should require iv and log an error for missing iv
def test_decrypt_requires_iv_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(ValueError, match=r"requires an IV/Counter"):
        ctr.decrypt(b"\x00", iv=None, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=iv" in error_calls[0]
    assert "CTR validation failed" in error_calls[0]


# decrypt should reject non-bytes ciphertext and log an error
def test_decrypt_rejects_wrong_ciphertext_type_and_logs_error(monkeypatch):
    error_calls: list[str] = []
    success_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))

    key = b"\x00" * 16
    iv = b"\x01" * 16
    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(TypeError, match=r"ciphertext must be bytes"):
        ctr.decrypt("not-bytes", iv=iv, unpadding="NONE")

    assert success_calls == []
    assert len(error_calls) == 1
    assert "step=ciphertext_type" in error_calls[0]


# decrypt should reject invalid iv values and log exactly one error
@pytest.mark.parametrize("bad_iv", [b"", b"\x00" * 15, b"\x00" * 17, "00" * 16, 123])
def test_decrypt_rejects_bad_iv_and_logs_error(monkeypatch, bad_iv):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = b"\x00" * 16
    ctr = mode_ctr.AESCTR(key)

    with pytest.raises(Exception):
        ctr.decrypt(b"\x00", iv=bad_iv, unpadding="NONE")  # type: ignore[arg-type]

    assert success_calls == []
    assert len(error_calls) == 1
    assert "CTR decrypt_raw failed" in error_calls[0]
    assert "module=mode_ctr" in error_calls[0]
    assert "func=decrypt" in error_calls[0]
    assert "step=decrypt_raw" in error_calls[0]

# -----------------------------------------------------------------------------
# Official AES reference test vectors from NIST publications
#
# NIST (U.S.) = National Institute of Standards and Technology
#
# They publish the canonical AES specification and example ciphertext outputs
# (known as test vectors) used to verify correct AES implementations.
#
# In the tests below, used are:
#   - SP 800-38A (Appendix F): CTR mode encryption/decryption examples. Link: https://dx.doi.org/10.6028/NIST.SP.800-38A
#
# Purpose:
#   These vectors allow us to assert that our CTR implementation produces identical results to the official NIST defined outputs.
#   If these tests pass, we know our CTR logic is compliant with the standard.
#
# NB:
#  padding and unpadding must be NONE in CTR mode.
# -----------------------------------------------------------------------------

# CTR: SP 800-38A Appendix F.5.1 (CTR-AES128.Encrypt)
# PDF page 55
def test_encrypt_decrypt_matches_nist_sp800_38a_vector(monkeypatch):
    success_calls: list[str] = []
    error_calls: list[str] = []

    monkeypatch.setattr(mode_ctr, "log_success", lambda msg: success_calls.append(msg))
    monkeypatch.setattr(mode_ctr, "log_error", lambda msg: error_calls.append(msg))

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    expected_ct = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    )

    ctr = mode_ctr.AESCTR(key)

    ct, out_iv = ctr.encrypt_with_iv(pt, iv=iv, padding="NONE")
    assert out_iv == iv
    assert ct == expected_ct

    back = ctr.decrypt(ct, iv=iv, unpadding="NONE")
    assert back == pt

    assert error_calls == []
    assert len(success_calls) == 2  # encrypt + decrypt
