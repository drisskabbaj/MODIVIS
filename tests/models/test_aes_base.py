import pytest

import src.models.aes_base as aes_base

# _ensure_bytes should accept bytes, bytearray, str and return bytes
def test_ensure_bytes_accepts_bytes_bytearray_and_str():
    assert aes_base._ensure_bytes(b"ABC") == b"ABC"
    assert aes_base._ensure_bytes(bytearray(b"ABC")) == b"ABC"
    assert aes_base._ensure_bytes("ABC") == b"ABC"


# _ensure_bytes should reject wrong types
@pytest.mark.parametrize("value", [123, None, object()])
def test_ensure_bytes_rejects_wrong_type(value):
    with pytest.raises(TypeError, match=r"Expected bytes, bytearray, or string\."):
        aes_base._ensure_bytes(value)

# _check_key should accept only 16/24/32 bytes
@pytest.mark.parametrize("n", [16, 24, 32])
def test_check_key_accepts_valid_lengths(n):
    aes_base._check_key(b"\x00" * n)  # no raise


# _check_key should reject other sizes with a clear message
@pytest.mark.parametrize("n", [0, 1, 15, 17, 23, 25, 31, 33])
def test_check_key_rejects_invalid_lengths(n):
    with pytest.raises(ValueError, match=r"Invalid AES key length"):
        aes_base._check_key(b"\x00" * n)

# _require_iv should reject missing iv
def test_require_iv_none_raises():
    with pytest.raises(ValueError, match=r"requires an IV/Counter"):
        aes_base._require_iv(None, "CBC")


# _require_iv should reject wrong iv type
def test_require_iv_wrong_type_raises():
    with pytest.raises(TypeError, match=r"IV/Counter must be bytes"):
        aes_base._require_iv("00" * 16, "CBC")


# _require_iv should reject wrong length
@pytest.mark.parametrize("n", [0, 1, 15, 17, 31])
def test_require_iv_wrong_length_raises(n):
    with pytest.raises(ValueError, match=r"must be exactly 16 bytes"):
        aes_base._require_iv(b"\x00" * n, "CTR")


# _require_iv should accept bytes and bytearray and always return bytes
def test_require_iv_accepts_bytes_and_bytearray():
    out1 = aes_base._require_iv(b"\x01" * 16, "CBC")
    out2 = aes_base._require_iv(bytearray(b"\x02" * 16), "CTR")
    assert isinstance(out1, bytes) and out1 == b"\x01" * 16
    assert isinstance(out2, bytes) and out2 == b"\x02" * 16

# _require_block_aligned should accept multiple of 16
def test_require_block_aligned_accepts_multiple():
    aes_base._require_block_aligned(b"A" * 16, context="Plaintext")
    aes_base._require_block_aligned(b"A" * 32, context="Ciphertext")


# _require_block_aligned should reject non multiple of 16
def test_require_block_aligned_rejects_non_multiple():
    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        aes_base._require_block_aligned(b"A" * 15, context="Plaintext")

# AESCore should accept key as bytes/bytearray/str and normalize to bytes
def test_aescore_init_accepts_key_types():
    c1 = aes_base.AESCore(b"\x00" * 16)
    c2 = aes_base.AESCore(bytearray(b"\x00" * 16))
    c3 = aes_base.AESCore("A" * 16)  # 16 UTF-8 bytes

    assert isinstance(c1.key, bytes) and len(c1.key) == 16
    assert isinstance(c2.key, bytes) and len(c2.key) == 16
    assert isinstance(c3.key, bytes) and len(c3.key) == 16


# AESCore should reject invalid key length
def test_aescore_init_rejects_invalid_key_length():
    with pytest.raises(ValueError, match=r"Invalid AES key length"):
        aes_base.AESCore(b"\x00" * 15)


# encrypt_raw should reject wrong plaintext type
@pytest.mark.parametrize("value", ["ABC", 123, None])
def test_encrypt_raw_rejects_wrong_plaintext_type(value):
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(TypeError, match=r"Plaintext must be bytes"):
        core.encrypt_raw(value, "ECB")

# decrypt_raw should reject wrong ciphertext type
@pytest.mark.parametrize("value", ["0011", 123, None])
def test_decrypt_raw_rejects_wrong_ciphertext_type(value):
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(TypeError, match=r"Ciphertext must be bytes"):
        core.decrypt_raw(value, "ECB")

# encrypt_raw should reject invalid mode
def test_encrypt_raw_invalid_mode_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"Invalid AES mode"):
        core.encrypt_raw(b"A" * 16, "BLA")

# decrypt_raw should reject invalid mode
def test_decrypt_raw_invalid_mode_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"Invalid AES mode"):
        core.decrypt_raw(b"A" * 16, "BLA")

# encrypt_raw ECB must reject non block-aligned
def test_encrypt_raw_ecb_non_block_aligned_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        core.encrypt_raw(b"A" * 15, "ECB")

# decrypt_raw ECB must reject non block-aligned
def test_decrypt_raw_ecb_non_block_aligned_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"not a multiple of 16"):
        core.decrypt_raw(b"A" * 15, "ECB")

# CBC encrypt_raw requires IV and must raise if missing
def test_encrypt_raw_cbc_missing_iv_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"CBC requires an IV/Counter"):
        core.encrypt_raw(b"A" * 16, "CBC", iv=None)

# CTR encrypt_raw requires IV and must raise if missing
def test_encrypt_raw_ctr_missing_iv_raises():
    core = aes_base.AESCore(b"\x00" * 16)

    with pytest.raises(ValueError, match=r"CTR requires an IV/Counter"):
        core.encrypt_raw(b"A", "CTR", iv=None)

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
# -----------------------------------------------------------------------------


# ECB: SP 800-38A Appendix F.1.1 (ECB-AES128.Encrypt) 
# PDF page 24
def test_encrypt_decrypt_raw_ecb_matches_nist_sp800_38a_vector():

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

    core = aes_base.AESCore(key)

    ct = core.encrypt_raw(pt, "ECB")
    assert ct == expected_ct

    back = core.decrypt_raw(ct, "ECB")
    assert back == pt


# CBC: SP 800-38A Appendix F.2.1 (CBC-AES128.Encrypt)
# PDF page 27
def test_encrypt_decrypt_raw_cbc_matches_nist_sp800_38a_vector():

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

    core = aes_base.AESCore(key)

    ct = core.encrypt_raw(pt, "CBC", iv=iv)
    assert ct == expected_ct

    back = core.decrypt_raw(ct, "CBC", iv=iv)
    assert back == pt


# CTR: SP 800-38A Appendix F.5.1 (CTR-AES128.Encrypt)
# PDF page 55
def test_encrypt_decrypt_raw_ctr_matches_nist_sp800_38a_vector():

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

    core = aes_base.AESCore(key)

    ct = core.encrypt_raw(pt, "CTR", iv=iv)
    assert ct == expected_ct

    back = core.decrypt_raw(ct, "CTR", iv=iv)
    assert back == pt


# AESAVS (6.2 - The Known Answer Tests) sample dataset
# PDF page 5
def test_encrypt_decrypt_raw_ecb_matches_nist_aesavs_kat_sample_dataset():

    key = bytes.fromhex("00" * 16)
    pt = bytes.fromhex("6a84867cd77e12ad07ea1be895c53fa3")
    expected_ct = bytes.fromhex("732281c0a0aab8f7a54a0c67a0c45ecf")

    core = aes_base.AESCore(key)

    ct = core.encrypt_raw(pt, "ECB")
    assert ct == expected_ct

    back = core.decrypt_raw(ct, "ECB")
    assert back == pt

# AESAVS (6.3 - The Multi-block Message Test) sample dataset
# PDF page 6
def test_encrypt_decrypt_raw_cbc_matches_nist_aesavs_mmt_sample_dataset():

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

    core = aes_base.AESCore(key)

    ct = core.encrypt_raw(pt, "CBC", iv=iv)
    assert ct == expected_ct

    back = core.decrypt_raw(ct, "CBC", iv=iv)
    assert back == pt
    