import pytest

import src.services.crypto_workflow as crypto_workflow

# helper stub for ECB (deterministic and no real crypto)
class _ECBStub:
    def __init__(self, key: bytes):
        self.key = key
        self.calls: list[tuple[bytes, str]] = []

    def encrypt(self, plaintext: bytes, padding: str) -> bytes:
        self.calls.append((plaintext, padding))
        return b"ECB_CT|" + plaintext

    def decrypt(self, ciphertext: bytes, unpadding: str) -> bytes:
        self.calls.append((ciphertext, unpadding))
        if ciphertext.startswith(b"ECB_CT|"):
            return ciphertext[len(b"ECB_CT|") :]
        return b"RAW|" + ciphertext


# helper stub for CBC (deterministic and returns used iv)
class _CBCStub:
    def __init__(self, key: bytes):
        self.key = key
        self.calls: list[tuple[str, bytes, bytes | None, str]] = []

    def encrypt_with_iv(self, plaintext: bytes, iv: bytes | None, padding: str):
        self.calls.append(("enc", plaintext, iv, padding))
        used_iv = iv if iv is not None else b"\x11" * 16
        return (b"CBC_CT|" + plaintext, used_iv)

    def decrypt(self, ciphertext: bytes, iv: bytes, unpadding: str) -> bytes:
        self.calls.append(("dec", ciphertext, iv, unpadding))
        if ciphertext.startswith(b"CBC_CT|"):
            return ciphertext[len(b"CBC_CT|") :]
        return b"RAW|" + ciphertext


# helper stub for CTR (deterministic and returns used iv)
class _CTRStub:
    def __init__(self, key: bytes):
        self.key = key
        self.calls: list[tuple[str, bytes, bytes | None, str]] = []

    def encrypt_with_iv(self, plaintext: bytes, iv: bytes | None, padding: str):
        self.calls.append(("enc", plaintext, iv, padding))
        used_iv = iv if iv is not None else b"\x22" * 16
        return (b"CTR_CT|" + plaintext, used_iv)

    def decrypt(self, ciphertext: bytes, iv: bytes, unpadding: str) -> bytes:
        self.calls.append(("dec", ciphertext, iv, unpadding))
        if ciphertext.startswith(b"CTR_CT|"):
            return ciphertext[len(b"CTR_CT|") :]
        return b"RAW|" + ciphertext


def _call_encrypt(**overrides):
    base = dict(
        mode="ECB",
        plaintext="A",
        input_format="TEXT",
        key_hex="00" * 16,
        iv_hex=None,
        padding_mode="NONE",
    )
    base.update(overrides)
    return crypto_workflow.encrypt_workflow(**base)


def _call_decrypt(**overrides):
    base = dict(
        mode="ECB",
        ciphertext_hex="00" * 16,
        key_hex="00" * 16,
        iv_hex=None,
        unpadding_mode="NONE",
    )
    base.update(overrides)
    return crypto_workflow.decrypt_workflow(**base)


# normalize_mode should strip spaces and uppercase mode
def test_normalize_mode_strips_and_uppercases():
    assert crypto_workflow.normalize_mode(" ecb ") == "ECB"
    assert crypto_workflow.normalize_mode("\ncbc\t") == "CBC"
    assert crypto_workflow.normalize_mode("CTR") == "CTR"


# normalize_mode should be safe with None and return empty string
def test_normalize_mode_is_safe_with_none():
    assert crypto_workflow.normalize_mode(None) == ""


# ensure_supported_mode should accept ECB/CBC/CTR
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
def test_ensure_supported_mode_accepts_valid_modes(mode):
    out = crypto_workflow.ensure_supported_mode(mode)
    assert out == mode


# ensure_supported_mode should reject invalid mode with WorkflowError fields
def test_ensure_supported_mode_rejects_invalid_mode_with_workflowerror():
    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.ensure_supported_mode("BLA")

    e = ei.value
    assert e.code == "UNSUPPORTED_MODE"
    assert e.field == "mode"
    assert "Unsupported mode" in e.message


# generate_key_hex should call generator with correct bytes length and return hex
@pytest.mark.parametrize("bits,expected_len", [(128, 16), (192, 24), (256, 32)])
def test_generate_key_hex_calls_generator_with_bytes_and_returns_hex(monkeypatch, bits, expected_len):
    calls: list[tuple[int, dict]] = []

    def _fake_generate_random_key(nbytes: int, **kwargs):
        calls.append((nbytes, kwargs))
        return b"\xAB" * nbytes

    monkeypatch.setattr(crypto_workflow, "generate_random_key", _fake_generate_random_key)
    monkeypatch.setattr(crypto_workflow, "hex_from_bytes", lambda b, **kwargs: b.hex())

    out = crypto_workflow.generate_key_hex(bits)

    assert out == ("ab" * expected_len)
    assert calls == [(expected_len, {"label": "SERVICE", "purpose": "generate_key_hex"})]


# generate_key_hex should reject invalid bits with WorkflowError
@pytest.mark.parametrize("bits", [0, 64, 129, 512, -1])
def test_generate_key_hex_rejects_invalid_bit_sizes(bits):
    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.generate_key_hex(bits)

    e = ei.value
    assert e.code == "INVALID_KEY_SIZE"
    assert e.field == "key"
    assert "128, 192, or 256" in e.message


# generate_iv_hex should call generator and return hex
def test_generate_iv_hex_calls_generator_and_returns_hex(monkeypatch):
    calls: list[dict] = []

    def _fake_generate_random_iv(**kwargs):
        calls.append(kwargs)
        return b"\xCD" * 16

    monkeypatch.setattr(crypto_workflow, "generate_random_iv", _fake_generate_random_iv)
    monkeypatch.setattr(crypto_workflow, "hex_from_bytes", lambda b, **kwargs: b.hex())

    out = crypto_workflow.generate_iv_hex()

    assert out == ("cd" * 16)
    assert calls == [{"label": "SERVICE", "purpose": "generate_iv_hex"}]

# encrypt_workflow and decrypt_workflow should wrap key parse errors into WorkflowError INVALID_KEY
@pytest.mark.parametrize("kind", ["encrypt", "decrypt"])
def test_workflow_wraps_key_parse_error_into_workflowerror(monkeypatch, kind):
    def _bad_key(_):
        raise ValueError("Key (HEX) is invalid HEX")

    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", _bad_key)

    if kind == "encrypt":
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            _call_encrypt(
                mode="ECB",
                plaintext="ABC",
                input_format="TEXT",
                key_hex="zz11",
                padding_mode="PKCS7",
            )
    else:
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            _call_decrypt(
                mode="ECB",
                ciphertext_hex="00" * 16,
                key_hex="zz11",
            )

    e = ei.value
    assert e.code == "INVALID_KEY"
    assert e.field == "key"
    assert "invalid HEX" in e.message
    assert "ValueError" in e.details

# encrypt_workflow and decrypt_workflow should reject invalid AES key lengths after parsing
@pytest.mark.parametrize("kind", ["encrypt", "decrypt"])
def test_workflow_rejects_invalid_key_length_after_parse(monkeypatch, kind):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 15)

    caller = _call_encrypt if kind == "encrypt" else _call_decrypt
    if kind == "decrypt":
        monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        if kind == "encrypt":
            caller(
                mode="ECB",
                plaintext="ABC",
                input_format="TEXT",
                key_hex="00" * 15,
                iv_hex=None,
                padding_mode="PKCS7",
            )
        else:
            caller(
                mode="ECB",
                ciphertext_hex="aa" * 16,
                key_hex="00" * 15,
                iv_hex=None,
                unpadding_mode="NONE",
            )

    e = ei.value
    assert e.code == "INVALID_KEY"
    assert e.field == "key"
    assert "16/24/32" in e.message
    assert "len=15" in e.details


# encrypt_workflow should wrap plaintext parse errors into WorkflowError INVALID_INPUT
def test_encrypt_workflow_wraps_plaintext_parse_error(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)

    def _bad_plaintext(_, __):
        raise ValueError("Input parsing failed")

    monkeypatch.setattr(crypto_workflow, "parse_plaintext", _bad_plaintext)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.encrypt_workflow(
            mode="ECB",
            plaintext="0xGG",
            input_format="HEX",
            key_hex="00" * 16,
            iv_hex=None,
            padding_mode="PKCS7",
        )

    e = ei.value
    assert e.code == "INVALID_INPUT"
    assert e.field == "plaintext"
    assert "Input parsing failed" in e.message


# encrypt_workflow CTR should reject any padding that is not NONE
def test_encrypt_workflow_ctr_rejects_padding(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"abc")

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.encrypt_workflow(
            mode="CTR",
            plaintext="abc",
            input_format="TEXT",
            key_hex="00" * 16,
            iv_hex=None,
            padding_mode="PKCS7",
        )

    e = ei.value
    assert e.code == "PADDING_NOT_ALLOWED"
    assert e.field == "padding"
    assert "CTR does not use padding" in e.message


# encrypt_workflow ECB and CBC should reject non block-aligned plaintext when padding=NONE
@pytest.mark.parametrize("mode", ["ECB", "CBC"])
def test_encrypt_workflow_padding_none_requires_block_alignment_for_ecb_cbc(monkeypatch, mode):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"A" * 15)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.encrypt_workflow(
            mode=mode,
            plaintext="A" * 15,
            input_format="TEXT",
            key_hex="00" * 16,
            iv_hex=None,
            padding_mode="NONE",
        )

    e = ei.value
    assert e.code == "PLAINTEXT_NOT_BLOCK_ALIGNED"
    assert e.field == "plaintext"
    assert "multiple of 16" in e.message


# encrypt_workflow ECB should apply padding details and call AESECB.encrypt with padding=NONE
def test_encrypt_workflow_ecb_applies_padding_and_calls_ecb_encrypt_with_padding_none(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x01" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"HELLO")

    padded = b"HELLO" + b"\x0b" * 11
    monkeypatch.setattr(
        crypto_workflow,
        "pad_with_info",
        lambda data, block_size, mode, **kwargs: (padded, 11, b"\x0b" * 11),
    )

    created: list[_ECBStub] = []

    def _mk_ecb(key: bytes):
        inst = _ECBStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESECB", _mk_ecb)

    out = crypto_workflow.encrypt_workflow(
        mode="ECB",
        plaintext="HELLO",
        input_format="TEXT",
        key_hex="01" * 16,
        iv_hex=None,
        padding_mode="PKCS7",
    )

    assert out.mode == "ECB"
    assert out.key == b"\x01" * 16
    assert out.plaintext == b"HELLO"
    assert out.padded_plaintext == padded
    assert out.pad_len == 11
    assert out.pad_bytes == b"\x0b" * 11
    assert out.used_iv is None
    assert out.ciphertext == b"ECB_CT|" + padded

    assert len(created) == 1
    assert created[0].calls == [(padded, "NONE")]


# encrypt_workflow CBC should parse IV and pass bytes to model
def test_encrypt_workflow_cbc_parses_iv_and_passes_it_to_model(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x02" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"DATA")

    monkeypatch.setattr(
        crypto_workflow,
        "pad_with_info",
        lambda data, block_size, mode, **kwargs: (b"DATA" + b"\x0c" * 12, 12, b"\x0c" * 12),
    )

    iv_bytes = b"\x99" * 16
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: iv_bytes)

    created: list[_CBCStub] = []

    def _mk_cbc(key: bytes):
        inst = _CBCStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCBC", _mk_cbc)

    out = crypto_workflow.encrypt_workflow(
        mode="CBC",
        plaintext="DATA",
        input_format="TEXT",
        key_hex="02" * 16,
        iv_hex="99" * 16,
        padding_mode="PKCS7",
    )

    assert out.mode == "CBC"
    assert out.used_iv == iv_bytes
    assert out.ciphertext.startswith(b"CBC_CT|")
    assert len(created) == 1

    kind, passed_pt, passed_iv, passed_pad = created[0].calls[0]
    assert kind == "enc"
    assert passed_iv == iv_bytes
    assert passed_pad == "NONE"
    assert passed_pt == out.padded_plaintext


# encrypt_workflow CBC should allow missing IV and return auto generated used_iv from model
def test_encrypt_workflow_cbc_missing_iv_uses_model_generated_iv(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x10" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"DATA")

    monkeypatch.setattr(
        crypto_workflow,
        "pad_with_info",
        lambda data, block_size, mode, **kwargs: (b"DATA" + b"\x0c" * 12, 12, b"\x0c" * 12),
    )

    def _iv_parser_should_not_be_called(*args, **kwargs):
        raise AssertionError("parse_iv_hex must not be called when iv_hex is missing")

    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", _iv_parser_should_not_be_called)

    created: list[_CBCStub] = []

    def _mk_cbc(key: bytes):
        inst = _CBCStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCBC", _mk_cbc)

    out = crypto_workflow.encrypt_workflow(
        mode="CBC",
        plaintext="DATA",
        input_format="TEXT",
        key_hex="10" * 16,
        iv_hex=None,
        padding_mode="PKCS7",
    )

    assert out.mode == "CBC"
    assert out.used_iv == (b"\x11" * 16)
    assert len(created) == 1

    kind, passed_pt, passed_iv, passed_pad = created[0].calls[0]
    assert kind == "enc"
    assert passed_iv is None
    assert passed_pad == "NONE"
    assert passed_pt == out.padded_plaintext


# encrypt_workflow and decrypt_workflow should reject IV that is not exactly 16 bytes
@pytest.mark.parametrize("kind", ["encrypt", "decrypt"])
def test_workflow_iv_wrong_length_raises_invalid_iv(monkeypatch, kind):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: b"\x00" * 15)

    if kind == "encrypt":
        monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"A" * 16)
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            crypto_workflow.encrypt_workflow(
                mode="CBC",
                plaintext="A" * 16,
                input_format="TEXT",
                key_hex="00" * 16,
                iv_hex="00" * 15,
                padding_mode="NONE",
            )
    else:
        monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            crypto_workflow.decrypt_workflow(
                mode="CBC",
                ciphertext_hex="aa" * 16,
                key_hex="00" * 16,
                iv_hex="00" * 15,
                unpadding_mode="NONE",
            )

    e = ei.value
    assert e.code == "INVALID_IV"
    assert e.field == "iv"
    assert "exactly 16 bytes" in e.message
    assert "len=15" in e.details


# encrypt_workflow CTR should not call pad_with_info and should use plaintext directly
def test_encrypt_workflow_ctr_does_not_call_padding_and_uses_plaintext_directly(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x03" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"CTR_DATA")

    def _pad_should_not_be_called(*args, **kwargs):
        raise AssertionError("pad_with_info must not be called in CTR mode")

    monkeypatch.setattr(crypto_workflow, "pad_with_info", _pad_should_not_be_called)

    created: list[_CTRStub] = []

    def _mk_ctr(key: bytes):
        inst = _CTRStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCTR", _mk_ctr)

    out = crypto_workflow.encrypt_workflow(
        mode="CTR",
        plaintext="CTR_DATA",
        input_format="TEXT",
        key_hex="03" * 16,
        iv_hex=None,
        padding_mode="NONE",
    )

    assert out.mode == "CTR"
    assert out.plaintext == b"CTR_DATA"
    assert out.padded_plaintext == b"CTR_DATA"
    assert out.pad_len == 0
    assert out.pad_bytes == b""
    assert out.used_iv == (b"\x22" * 16)
    assert out.ciphertext == b"CTR_CT|CTR_DATA"

    assert len(created) == 1
    kind, passed_pt, passed_iv, passed_pad = created[0].calls[0]
    assert kind == "enc"
    assert passed_pt == b"CTR_DATA"
    assert passed_pad == "NONE"
    assert passed_iv is None


# encrypt_workflow CTR should parse IV and pass it into the model
def test_encrypt_workflow_ctr_parses_iv_and_passes_it_to_model(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x20" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"CTR_DATA")

    iv_bytes = b"\x33" * 16
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: iv_bytes)

    created: list[_CTRStub] = []

    def _mk_ctr(key: bytes):
        inst = _CTRStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCTR", _mk_ctr)

    out = crypto_workflow.encrypt_workflow(
        mode="CTR",
        plaintext="CTR_DATA",
        input_format="TEXT",
        key_hex="20" * 16,
        iv_hex="33" * 16,
        padding_mode="NONE",
    )

    assert out.mode == "CTR"
    assert out.used_iv == iv_bytes
    assert out.ciphertext == b"CTR_CT|CTR_DATA"
    assert len(created) == 1

    kind, passed_pt, passed_iv, passed_pad = created[0].calls[0]
    assert kind == "enc"
    assert passed_pt == b"CTR_DATA"
    assert passed_iv == iv_bytes
    assert passed_pad == "NONE"


# encrypt_workflow should wrap pad_with_info errors into WorkflowError INVALID_PADDING
def test_encrypt_workflow_wraps_padding_error(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"A" * 16)

    def _bad_pad(*args, **kwargs):
        raise ValueError("Padding failed: unsupported padding mode")

    monkeypatch.setattr(crypto_workflow, "pad_with_info", _bad_pad)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.encrypt_workflow(
            mode="ECB",
            plaintext="A" * 16,
            input_format="TEXT",
            key_hex="00" * 16,
            iv_hex=None,
            padding_mode="BLA",  
        )

    e = ei.value
    assert e.code == "INVALID_PADDING"
    assert e.field == "padding"
    assert "Padding failed" in e.message


# encrypt_workflow and decrypt_workflow should wrap IV parse errors into WorkflowError INVALID_IV
@pytest.mark.parametrize("kind", ["encrypt", "decrypt"])
def test_workflow_wraps_iv_parse_error(monkeypatch, kind):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)

    def _bad_iv(*args, **kwargs):
        raise ValueError("IV/Counter (HEX) is invalid HEX")

    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", _bad_iv)

    if kind == "encrypt":
        monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"A" * 16)
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            crypto_workflow.encrypt_workflow(
                mode="CBC",
                plaintext="A" * 16,
                input_format="TEXT",
                key_hex="00" * 16,
                iv_hex="zz",
                padding_mode="NONE",
            )
    else:
        monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)
        with pytest.raises(crypto_workflow.WorkflowError) as ei:
            crypto_workflow.decrypt_workflow(
                mode="CBC",
                ciphertext_hex="aa" * 16,
                key_hex="00" * 16,
                iv_hex="zz",
                unpadding_mode="NONE",
            )

    e = ei.value
    assert e.code == "INVALID_IV"
    assert e.field == "iv"
    assert "invalid HEX" in e.message


# encrypt_workflow should convert unexpected model exceptions into WorkflowError INTERNAL
def test_encrypt_workflow_unexpected_model_error_is_internal(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_plaintext", lambda s, fmt: b"A" * 16)
    monkeypatch.setattr(crypto_workflow, "pad_with_info", lambda *a, **k: (b"A" * 16, 0, b""))

    class _BadECB:
        def __init__(self, key: bytes):
            pass

        def encrypt(self, plaintext: bytes, padding: str) -> bytes:
            raise RuntimeError("boom")

    monkeypatch.setattr(crypto_workflow, "AESECB", _BadECB)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.encrypt_workflow(
            mode="ECB",
            plaintext="A" * 16,
            input_format="TEXT",
            key_hex="00" * 16,
            iv_hex=None,
            padding_mode="NONE",
        )

    e = ei.value
    assert e.code == "INTERNAL"
    assert "Encryption failed" in e.message


# decrypt_workflow should wrap ciphertext parse errors into WorkflowError INVALID_CIPHERTEXT
def test_decrypt_workflow_wraps_ciphertext_parse_error(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)

    def _bad_ct(_):
        raise ValueError("Ciphertext (HEX) is invalid HEX")

    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", _bad_ct)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode="ECB",
            ciphertext_hex="zz",
            key_hex="00" * 16,
            iv_hex=None,
            unpadding_mode="NONE",
        )

    e = ei.value
    assert e.code == "INVALID_CIPHERTEXT"
    assert e.field == "ciphertext"
    assert "invalid HEX" in e.message


# decrypt_workflow CTR should reject any unpadding that is not NONE
def test_decrypt_workflow_ctr_rejects_unpadding(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA")

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode="CTR",
            ciphertext_hex="aa",
            key_hex="00" * 16,
            iv_hex="00" * 16,
            unpadding_mode="PKCS7",
        )

    e = ei.value
    assert e.code == "UNPADDING_NOT_ALLOWED"
    assert e.field == "unpadding"
    assert "CTR does not use unpadding" in e.message


# decrypt_workflow ECB and CBC should reject non block-aligned ciphertext
@pytest.mark.parametrize("mode", ["ECB", "CBC"])
def test_decrypt_workflow_requires_block_aligned_ciphertext_for_ecb_cbc(monkeypatch, mode):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 15)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode=mode,
            ciphertext_hex="aa" * 15,
            key_hex="00" * 16,
            iv_hex=("00" * 16 if mode == "CBC" else None),
            unpadding_mode="NONE",
        )

    e = ei.value
    assert e.code == "CIPHERTEXT_NOT_BLOCK_ALIGNED"
    assert e.field == "ciphertext"
    assert "multiple of 16" in e.message


# decrypt_workflow CBC and CTR should require IV
@pytest.mark.parametrize("mode", ["CBC", "CTR"])
def test_decrypt_workflow_requires_iv_for_cbc_and_ctr(monkeypatch, mode):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode=mode,
            ciphertext_hex="aa" * 16,
            key_hex="00" * 16,
            iv_hex=None,
            unpadding_mode="NONE",
        )

    e = ei.value
    assert e.code == "MISSING_IV"
    assert e.field == "iv"
    assert "requires the same IV/Counter" in e.message


# decrypt_workflow ECB should call unpad_with_info and return removed pad bytes
def test_decrypt_workflow_ecb_calls_unpad_with_info_and_returns_removed_pad(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x04" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA" * 16)

    monkeypatch.setattr(crypto_workflow, "AESECB", lambda key: _ECBStub(key))

    raw = b"HELLO" + b"\x0b" * 11
    monkeypatch.setattr(_ECBStub, "decrypt", lambda self, ct, unpadding: raw)

    monkeypatch.setattr(
        crypto_workflow,
        "unpad_with_info",
        lambda data, block_size, mode, **kwargs: (b"HELLO", b"\x0b" * 11),
    )

    out = crypto_workflow.decrypt_workflow(
        mode="ECB",
        ciphertext_hex="aa" * 16,
        key_hex="04" * 16,
        iv_hex=None,
        unpadding_mode="PKCS7",
    )

    assert out.mode == "ECB"
    assert out.key == b"\x04" * 16
    assert out.ciphertext == b"\xAA" * 16
    assert out.raw_decrypted == raw
    assert out.plaintext_final == b"HELLO"
    assert out.removed_pad == b"\x0b" * 11
    assert out.used_iv is None


# decrypt_workflow should succeed with unpadding NONE and not call unpad_with_info
def test_decrypt_workflow_ecb_success_with_unpadding_none(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x30" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA" * 16)

    def _unpad_should_not_be_called(*args, **kwargs):
        raise AssertionError("unpad_with_info must not be called when unpadding_mode is NONE")

    monkeypatch.setattr(crypto_workflow, "unpad_with_info", _unpad_should_not_be_called)

    monkeypatch.setattr(crypto_workflow, "AESECB", lambda key: _ECBStub(key))
    monkeypatch.setattr(_ECBStub, "decrypt", lambda self, ct, unpadding: b"PLAINTEXT")

    out = crypto_workflow.decrypt_workflow(
        mode="ECB",
        ciphertext_hex="aa" * 16,
        key_hex="30" * 16,
        iv_hex=None,
        unpadding_mode="NONE",
    )

    assert out.mode == "ECB"
    assert out.raw_decrypted == b"PLAINTEXT"
    assert out.plaintext_final == b"PLAINTEXT"
    assert out.removed_pad == b""
    assert out.used_iv is None


# decrypt_workflow CBC should decrypt with IV and return used_iv
def test_decrypt_workflow_cbc_success_with_iv(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x40" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA" * 16)

    iv_bytes = b"\x44" * 16
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: iv_bytes)

    created: list[_CBCStub] = []

    def _mk_cbc(key: bytes):
        inst = _CBCStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCBC", _mk_cbc)

    def _decrypt_and_log(self, ct, iv, unpadding):
        self.calls.append(("dec", ct, iv, unpadding))
        return b"CBC_PLAINTEXT"

    monkeypatch.setattr(_CBCStub, "decrypt", _decrypt_and_log)

    out = crypto_workflow.decrypt_workflow(
        mode="CBC",
        ciphertext_hex="aa" * 16,
        key_hex="40" * 16,
        iv_hex="44" * 16,
        unpadding_mode="NONE",
    )

    assert out.mode == "CBC"
    assert out.used_iv == iv_bytes
    assert out.raw_decrypted == b"CBC_PLAINTEXT"
    assert out.plaintext_final == b"CBC_PLAINTEXT"
    assert out.removed_pad == b""

    assert len(created) == 1
    kind, passed_ct, passed_iv, passed_unpad = created[0].calls[0]
    assert kind == "dec"
    assert passed_ct == b"\xAA" * 16
    assert passed_iv == iv_bytes
    assert passed_unpad == "NONE"

# decrypt_workflow should convert PaddingError into WorkflowError BAD_PADDING
def test_decrypt_workflow_bad_padding_is_converted_to_workflowerror(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x05" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA" * 16)

    monkeypatch.setattr(crypto_workflow, "AESECB", lambda key: _ECBStub(key))
    monkeypatch.setattr(_ECBStub, "decrypt", lambda self, ct, unpadding: b"RAW_PADDED")

    def _raise_padding_error(*args, **kwargs):
        raise crypto_workflow.PaddingError("invalid PKCS7 padding bytes")

    monkeypatch.setattr(crypto_workflow, "unpad_with_info", _raise_padding_error)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode="ECB",
            ciphertext_hex="aa" * 16,
            key_hex="05" * 16,
            iv_hex=None,
            unpadding_mode="PKCS7",
        )

    e = ei.value
    assert e.code == "BAD_PADDING"
    assert e.field == "unpadding"
    assert "Unpadding failed" in e.message
    assert "invalid PKCS7" in e.message


# decrypt_workflow should wrap non-PaddingError unpadding failures into INVALID_UNPADDING
def test_decrypt_workflow_wraps_unpadding_non_paddingerror(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)

    monkeypatch.setattr(crypto_workflow, "AESECB", lambda key: _ECBStub(key))
    monkeypatch.setattr(_ECBStub, "decrypt", lambda self, ct, unpadding: b"RAW_PADDED")

    def _unpad_raises_other(*args, **kwargs):
        raise RuntimeError("unexpected unpad failure")

    monkeypatch.setattr(crypto_workflow, "unpad_with_info", _unpad_raises_other)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode="ECB",
            ciphertext_hex="aa" * 16,
            key_hex="00" * 16,
            iv_hex=None,
            unpadding_mode="PKCS7",
        )

    e = ei.value
    assert e.code == "INVALID_UNPADDING"
    assert e.field == "unpadding"
    assert "unexpected unpad failure" in e.message


# decrypt_workflow CTR should not call unpad_with_info and must return plaintext directly
def test_decrypt_workflow_ctr_does_not_call_unpad_and_returns_plaintext_directly(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x06" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"CTR_CT|DATA")

    iv_bytes = b"\x77" * 16
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: iv_bytes)

    def _unpad_should_not_be_called(*args, **kwargs):
        raise AssertionError("unpad_with_info must not be called in CTR mode")

    monkeypatch.setattr(crypto_workflow, "unpad_with_info", _unpad_should_not_be_called)

    created: list[_CTRStub] = []

    def _mk_ctr(key: bytes):
        inst = _CTRStub(key)
        created.append(inst)
        return inst

    monkeypatch.setattr(crypto_workflow, "AESCTR", _mk_ctr)

    out = crypto_workflow.decrypt_workflow(
        mode="CTR",
        ciphertext_hex="(ignored by stubbed parser)",
        key_hex="06" * 16,
        iv_hex="77" * 16,
        unpadding_mode="NONE",
    )

    assert out.mode == "CTR"
    assert out.used_iv == iv_bytes
    assert out.raw_decrypted == b"DATA"
    assert out.plaintext_final == b"DATA"
    assert out.removed_pad == b""

    assert len(created) == 1
    kind, passed_ct, passed_iv, passed_unpad = created[0].calls[0]
    assert kind == "dec"
    assert passed_iv == iv_bytes
    assert passed_unpad == "NONE"


# decrypt_workflow should convert unexpected model exceptions into WorkflowError INTERNAL
def test_decrypt_workflow_unexpected_model_error_is_internal(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x00" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"A" * 16)

    class _BadECB:
        def __init__(self, key: bytes):
            pass

        def decrypt(self, ciphertext: bytes, unpadding: str) -> bytes:
            raise RuntimeError("boom")

    monkeypatch.setattr(crypto_workflow, "AESECB", _BadECB)

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        crypto_workflow.decrypt_workflow(
            mode="ECB",
            ciphertext_hex="aa" * 16,
            key_hex="00" * 16,
            iv_hex=None,
            unpadding_mode="NONE",
        )

    e = ei.value
    assert e.code == "INTERNAL"
    assert "Decryption failed" in e.message


# encrypt_workflow and decrypt_workflow should reject unsupported mode
@pytest.mark.parametrize("kind", ["encrypt", "decrypt"])
def test_workflow_rejects_unsupported_mode(kind):
    caller = _call_encrypt if kind == "encrypt" else _call_decrypt

    with pytest.raises(crypto_workflow.WorkflowError) as ei:
        if kind == "encrypt":
            caller(
                mode="BLA",  
                plaintext="A",
                input_format="TEXT",
                key_hex="00" * 16,
                iv_hex=None,
                padding_mode="NONE",
            )
        else:
            caller(
                mode="BLA",  
                ciphertext_hex="00" * 16,
                key_hex="00" * 16,
                iv_hex=None,
                unpadding_mode="NONE",
            )

    e = ei.value
    assert e.code == "UNSUPPORTED_MODE"
    assert e.field == "mode"


# decrypt_workflow CBC should call unpad_with_info when unpadding is enabled
def test_decrypt_workflow_cbc_calls_unpad_with_info(monkeypatch):
    monkeypatch.setattr(crypto_workflow, "parse_aes_key_hex", lambda _: b"\x55" * 16)
    monkeypatch.setattr(crypto_workflow, "parse_ciphertext_hex", lambda _: b"\xAA" * 16)

    iv_bytes = b"\x66" * 16
    monkeypatch.setattr(crypto_workflow, "parse_iv_hex", lambda s, **kwargs: iv_bytes)

    monkeypatch.setattr(crypto_workflow, "AESCBC", lambda key: _CBCStub(key))
    monkeypatch.setattr(_CBCStub, "decrypt", lambda self, ct, iv, unpadding: b"HELLO" + b"\x0b" * 11)

    calls: list[tuple[bytes, int, str]] = []

    def _fake_unpad(data, block_size, mode, **kwargs):
        calls.append((data, block_size, mode))
        return (b"HELLO", b"\x0b" * 11)

    monkeypatch.setattr(crypto_workflow, "unpad_with_info", _fake_unpad)

    out = crypto_workflow.decrypt_workflow(
        mode="CBC",
        ciphertext_hex="aa" * 16,
        key_hex="55" * 16,
        iv_hex="66" * 16,
        unpadding_mode="PKCS7",
    )

    assert out.mode == "CBC"
    assert out.used_iv == iv_bytes
    assert out.plaintext_final == b"HELLO"
    assert out.removed_pad == b"\x0b" * 11
    assert calls and calls[0][1] == 16


# _wrap should keep stable fields and include original exception type in details
def test_wrap_includes_exception_type_in_details():
    e = crypto_workflow._wrap(code="X", field="Y", e=ValueError("boom"))
    assert e.code == "X"
    assert e.field == "Y"
    assert e.message == "boom"
    assert "ValueError" in e.details


# WorkflowError __str__ should return message
def test_workflowerror_str_returns_message():
    e = crypto_workflow.WorkflowError(code="X", field="Y", message="hello")
    assert str(e) == "hello"
