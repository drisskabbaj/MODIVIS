import pytest
from dataclasses import dataclass

import src.viewmodels.encryption_viewmodel as evm

class DummyWorkflowError(Exception):
    # workflowError replacement used by the viewmodel
    def __init__(self, code: str, field: str, message: str, details: str = ""):
        super().__init__(message)
        self.code = code
        self.field = field
        self.message = message
        self.details = details


@dataclass(slots=True)
class DummyEncryptWorkflowResult:
    ciphertext: bytes
    key: bytes
    used_iv: bytes | None

    plaintext: bytes
    padded_plaintext: bytes
    pad_bytes: bytes
    pad_len: int


@dataclass(slots=True)
class DummyDecryptWorkflowResult:
    plaintext_final: bytes
    key: bytes
    used_iv: bytes | None

    raw_decrypted: bytes
    removed_pad: bytes


# Autoapplied
@pytest.fixture(autouse=True)
def _patch_workflow_error(monkeypatch):
    # EncryptionViewModel should catch our DummyWorkflowError via evm.WorkflowError
    monkeypatch.setattr(evm, "WorkflowError", DummyWorkflowError)

# CryptoResult should have stable defaults for UI fields
def test_cryptoresult_defaults_are_stable():
    r = evm.CryptoResult(ok=True)

    assert r.ok is True
    assert r.error == ""
    assert r.error_code == ""
    assert r.error_field == ""
    assert r.error_details == ""

    assert r.output_hex == ""
    assert r.output_hex_raw == ""
    assert r.output_text == ""

    assert r.used_key_hex == ""
    assert r.used_iv_hex == ""

    assert r.input_format == "TEXT"
    assert r.padding_mode == "PKCS7"
    assert r.unpadding_mode == "PKCS7"

# _best_effort_utf8 should decode valid UTF-8 bytes into text
def test_best_effort_utf8_returns_decoded_text_on_valid_utf8():
    assert evm.EncryptionViewModel._best_effort_utf8(b"Hello \xf0\x9f\x91\x8b") == "Hello \U0001F44B"


# _best_effort_utf8 should return a clear hint if bytes are not valid UTF-8
def test_best_effort_utf8_returns_hint_on_invalid_utf8():
    msg = evm.EncryptionViewModel._best_effort_utf8(b"\xff\xfe\xfa")
    assert "UTF-8 decoding failed" in msg


# _fail should use a default error message when message is empty
def test_fail_uses_default_message_when_message_is_empty():
    r = evm.EncryptionViewModel._fail(code="X", message="")

    assert r.ok is False
    assert r.error == "Operation failed."
    assert r.error_code == "X"
    assert r.error_field == ""
    assert r.error_details == ""


# _fail should build a predictable error result when message and fields exist
def test_fail_uses_given_message_and_fields():
    r = evm.EncryptionViewModel._fail(code="BAD", field="key", message="Nope", details="more")

    assert r.ok is False
    assert r.error == "Nope"
    assert r.error_code == "BAD"
    assert r.error_field == "key"
    assert r.error_details == "more"


# _unexpected_error should map unknown exceptions to INTERNAL without leaking a stack trace
def test_unexpected_error_maps_to_internal_without_trace_leak():
    r = evm.EncryptionViewModel._unexpected_error(RuntimeError("boom"))

    assert r.ok is False
    assert r.error_code == "INTERNAL"
    assert r.error == "An unexpected internal error occurred."
    assert "RuntimeError: boom" in r.error_details

# generate_key_hex should return backend generated HEX when backend succeeds
def test_generate_key_hex_success_calls_backend(monkeypatch):
    called = {}

    def fake_generate(bits: int) -> str:
        called["bits"] = bits
        return "deadbeef"

    monkeypatch.setattr(evm, "svc_generate_key_hex", fake_generate)

    vm = evm.EncryptionViewModel()
    out = vm.generate_key_hex(128)

    assert out == "deadbeef"
    assert called["bits"] == 128


# generate_key_hex should raise ValueError with workflow message when backend raises WorkflowError
def test_generate_key_hex_workflow_error_becomes_value_error(monkeypatch):
    def fake_generate(bits: int) -> str:
        raise DummyWorkflowError(code="KEY", field="key", message="Bad key", details="")

    monkeypatch.setattr(evm, "svc_generate_key_hex", fake_generate)

    vm = evm.EncryptionViewModel()
    with pytest.raises(ValueError, match=r"Bad key"):
        vm.generate_key_hex(128)


# generate_iv_hex should return backend generated HEX when backend succeeds
def test_generate_iv_hex_success_calls_backend(monkeypatch):
    called = {"n": 0}

    def fake_generate() -> str:
        called["n"] += 1
        return "00112233"

    monkeypatch.setattr(evm, "svc_generate_iv_hex", fake_generate)

    vm = evm.EncryptionViewModel()
    out = vm.generate_iv_hex()

    assert out == "00112233"
    assert called["n"] == 1


# generate_iv_hex should raise ValueError with workflow message when backend raises WorkflowError
def test_generate_iv_hex_workflow_error_becomes_value_error(monkeypatch):
    def fake_generate() -> str:
        raise DummyWorkflowError(code="IV", field="iv", message="Bad iv", details="")

    monkeypatch.setattr(evm, "svc_generate_iv_hex", fake_generate)

    vm = evm.EncryptionViewModel()
    with pytest.raises(ValueError, match=r"Bad iv"):
        vm.generate_iv_hex()

# encrypt should map a successful workflow result into CryptoResult and format output blocks
def test_encrypt_success_with_iv_formats_ciphertext_and_maps_fields(monkeypatch):
    calls: list[tuple[str, int, dict]] = []

    def fake_format(hex_str: str, block_bytes: int = 16, **kwargs) -> str:
        calls.append((hex_str, block_bytes, kwargs))
        return f"FMT({hex_str}|{block_bytes})"

    monkeypatch.setattr(evm, "format_hex_blocks", fake_format)

    dummy = DummyEncryptWorkflowResult(
        ciphertext=b"\x00" * 16,
        key=b"\x11" * 16,
        used_iv=b"\x22" * 16,
        plaintext=b"ABC",
        padded_plaintext=b"ABC" + b"\x0d" * 13,
        pad_bytes=b"\x0d" * 13,
        pad_len=13,
    )

    monkeypatch.setattr(evm, "encrypt_workflow", lambda **kwargs: dummy)

    vm = evm.EncryptionViewModel()
    r = vm.encrypt(
        mode="CBC",
        plaintext="ABC",
        input_format="TEXT",
        key_hex="11" * 16,
        iv_hex="22" * 16,
        padding_mode="PKCS7",
    )

    assert r.ok is True

    ct_hex = ("00" * 16)
    assert r.output_hex_raw == ct_hex
    assert r.output_hex == f"FMT({ct_hex}|{evm.AES_BLOCK_BYTES})"

    assert len(calls) == 6

    key_hex = "11" * 16
    iv_hex = "22" * 16
    input_hex = dummy.plaintext.hex()
    padded_hex = dummy.padded_plaintext.hex()
    pad_hex = dummy.pad_bytes.hex()

    assert calls == [
        (ct_hex, evm.AES_BLOCK_BYTES, {"label": "Ciphertext", "purpose": "encrypt_viewmodel"}),
        (key_hex, evm.AES_BLOCK_BYTES, {"label": "Key", "purpose": "encrypt_viewmodel"}),
        (iv_hex, evm.AES_BLOCK_BYTES, {"label": "IV", "purpose": "encrypt_viewmodel"}),
        (input_hex, evm.AES_BLOCK_BYTES, {"label": "Plaintext", "purpose": "encrypt_viewmodel"}),
        (padded_hex, evm.AES_BLOCK_BYTES, {"label": "Padded plaintext", "purpose": "encrypt_viewmodel"}),
        (pad_hex, evm.AES_BLOCK_BYTES, {"label": "Padding bytes", "purpose": "encrypt_viewmodel"}),
    ]

    assert r.used_key_hex == key_hex
    assert r.used_iv_hex == iv_hex

    assert r.input_format == "TEXT"
    assert r.padding_mode == "PKCS7"

    assert r.input_hex_raw == input_hex
    assert r.padded_input_hex_raw == padded_hex
    assert r.pad_hex_raw == pad_hex
    assert r.pad_len == 13


# encrypt should set used_iv_hex to empty string if workflow returns no IV
def test_encrypt_success_without_iv_sets_used_iv_hex_empty(monkeypatch):
    monkeypatch.setattr(evm, "format_hex_blocks", lambda h, b=evm.AES_BLOCK_BYTES, **kwargs: f"FMT({h})")

    dummy = DummyEncryptWorkflowResult(
        ciphertext=b"\xaa" * 16,
        key=b"\xbb" * 16,
        used_iv=None,
        plaintext=b"\x01\x02",
        padded_plaintext=b"\x01\x02" + b"\x0e" * 14,
        pad_bytes=b"\x0e" * 14,
        pad_len=14,
    )

    monkeypatch.setattr(evm, "encrypt_workflow", lambda **kwargs: dummy)

    vm = evm.EncryptionViewModel()
    r = vm.encrypt(
        mode="ECB",
        plaintext="0102",
        input_format="HEX",
        key_hex="bb" * 16,
        iv_hex=None,
        padding_mode="PKCS7",
    )

    assert r.ok is True
    assert r.used_iv_hex == ""


# encrypt should convert WorkflowError into a clean CryptoResult error object
def test_encrypt_workflow_error_is_mapped_to_fail_result(monkeypatch):
    def fake_encrypt_workflow(**kwargs):
        raise DummyWorkflowError(
            code="PLAINTEXT",
            field="plaintext",
            message="Plaintext invalid",
            details="Expected HEX",
        )

    monkeypatch.setattr(evm, "encrypt_workflow", fake_encrypt_workflow)

    vm = evm.EncryptionViewModel()
    r = vm.encrypt(
        mode="ECB",
        plaintext="ZZ",
        input_format="HEX",
        key_hex="00" * 16,
        iv_hex=None,
        padding_mode="PKCS7",
    )

    assert r.ok is False
    assert r.error_code == "PLAINTEXT"
    assert r.error_field == "plaintext"
    assert r.error == "Plaintext invalid"
    assert r.error_details == "Expected HEX"


# encrypt should convert unexpected exceptions into INTERNAL error result
def test_encrypt_unexpected_exception_is_mapped_to_internal(monkeypatch):
    def fake_encrypt_workflow(**kwargs):
        raise ValueError("kaboom")

    monkeypatch.setattr(evm, "encrypt_workflow", fake_encrypt_workflow)

    vm = evm.EncryptionViewModel()
    r = vm.encrypt(
        mode="CTR",
        plaintext="ABC",
        input_format="TEXT",
        key_hex="00" * 16,
        iv_hex="11" * 16,
        padding_mode="NONE",
    )

    assert r.ok is False
    assert r.error_code == "INTERNAL"
    assert r.error == "An unexpected internal error occurred."
    assert "ValueError: kaboom" in r.error_details

# decrypt should map a successful workflow result into CryptoResult and format output blocks
def test_decrypt_success_valid_utf8_formats_plaintext_and_maps_fields(monkeypatch):
    calls: list[tuple[str, int, dict]] = []

    def fake_format(hex_str: str, block_bytes: int = 16, **kwargs) -> str:
        calls.append((hex_str, block_bytes, kwargs))
        return f"FMT({hex_str}|{block_bytes})"

    monkeypatch.setattr(evm, "format_hex_blocks", fake_format)

    dummy = DummyDecryptWorkflowResult(
        plaintext_final=b"HELLO",
        key=b"\x10" * 16,
        used_iv=b"\x20" * 16,
        raw_decrypted=b"HELLO" + b"\x0b" * 11,
        removed_pad=b"\x0b" * 11,
    )

    monkeypatch.setattr(evm, "decrypt_workflow", lambda **kwargs: dummy)

    vm = evm.EncryptionViewModel()
    r = vm.decrypt(
        mode="CBC",
        ciphertext_hex="00" * 16,
        key_hex="10" * 16,
        iv_hex="20" * 16,
        unpadding_mode="PKCS7",
    )

    assert r.ok is True

    pt_hex = dummy.plaintext_final.hex()
    assert r.output_hex_raw == pt_hex
    assert r.output_hex == f"FMT({pt_hex}|{evm.AES_BLOCK_BYTES})"

    assert len(calls) == 6

    key_hex = "10" * 16
    iv_hex = "20" * 16
    ct_used = "00" * 16
    raw_hex = dummy.raw_decrypted.hex()
    removed_hex = dummy.removed_pad.hex()

    assert calls == [
        (pt_hex, evm.AES_BLOCK_BYTES, {"label": "Plaintext final", "purpose": "decrypt_viewmodel"}),
        (key_hex, evm.AES_BLOCK_BYTES, {"label": "Key", "purpose": "decrypt_viewmodel"}),
        (iv_hex, evm.AES_BLOCK_BYTES, {"label": "IV", "purpose": "decrypt_viewmodel"}),
        (ct_used, evm.AES_BLOCK_BYTES, {"assume_normalized": True, "label": "Ciphertext used", "purpose": "decrypt_viewmodel"}),
        (raw_hex, evm.AES_BLOCK_BYTES, {"label": "Raw decrypted", "purpose": "decrypt_viewmodel"}),
        (removed_hex, evm.AES_BLOCK_BYTES, {"label": "Removed padding", "purpose": "decrypt_viewmodel"}),
    ]

    assert r.output_text == "HELLO"
    assert r.used_key_hex == key_hex
    assert r.used_iv_hex == iv_hex

    assert r.unpadding_mode == "PKCS7"
    assert r.decrypted_raw_hex_raw == raw_hex
    assert r.removed_pad_hex_raw == removed_hex
    assert r.removed_pad_len == len(dummy.removed_pad)


# decrypt should show a clear hint message when plaintext is not valid UTF-8
def test_decrypt_success_invalid_utf8_sets_fallback_text(monkeypatch):
    monkeypatch.setattr(evm, "format_hex_blocks", lambda h, b=evm.AES_BLOCK_BYTES, **kwargs: h)

    dummy = DummyDecryptWorkflowResult(
        plaintext_final=b"\xff\xfe\xfa",
        key=b"\x00" * 16,
        used_iv=None,
        raw_decrypted=b"\xff\xfe\xfa",
        removed_pad=b"",
    )

    monkeypatch.setattr(evm, "decrypt_workflow", lambda **kwargs: dummy)

    vm = evm.EncryptionViewModel()
    r = vm.decrypt(
        mode="ECB",
        ciphertext_hex="aa",
        key_hex="00" * 16,
        iv_hex=None,
        unpadding_mode="NONE",
    )

    assert r.ok is True
    assert "UTF-8 decoding failed" in r.output_text
    assert r.used_iv_hex == ""


# decrypt should convert WorkflowError into a clean CryptoResult error object
def test_decrypt_workflow_error_is_mapped_to_fail_result(monkeypatch):
    def fake_decrypt_workflow(**kwargs):
        raise DummyWorkflowError(
            code="CIPHERTEXT",
            field="ciphertext",
            message="Ciphertext invalid",
            details="Odd length",
        )

    monkeypatch.setattr(evm, "decrypt_workflow", fake_decrypt_workflow)

    vm = evm.EncryptionViewModel()
    r = vm.decrypt(
        mode="ECB",
        ciphertext_hex="abc",
        key_hex="00" * 16,
        iv_hex=None,
        unpadding_mode="PKCS7",
    )

    assert r.ok is False
    assert r.error_code == "CIPHERTEXT"
    assert r.error_field == "ciphertext"
    assert r.error == "Ciphertext invalid"
    assert r.error_details == "Odd length"


# decrypt should convert unexpected exceptions into INTERNAL error result
def test_decrypt_unexpected_exception_is_mapped_to_internal(monkeypatch):
    def fake_decrypt_workflow(**kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(evm, "decrypt_workflow", fake_decrypt_workflow)

    vm = evm.EncryptionViewModel()
    r = vm.decrypt(
        mode="CTR",
        ciphertext_hex="00" * 16,
        key_hex="00" * 16,
        iv_hex="11" * 16,
        unpadding_mode="NONE",
    )

    assert r.ok is False
    assert r.error_code == "INTERNAL"
    assert r.error == "An unexpected internal error occurred."
    assert "RuntimeError: nope" in r.error_details

# encrypt should forward all UI arguments unchanged into encrypt_workflow
def test_encrypt_forwards_arguments_to_encrypt_workflow(monkeypatch):
    captured_calls: list[dict] = []

    dummy = DummyEncryptWorkflowResult(
        ciphertext=b"\x00" * 16,
        key=b"\x11" * 16,
        used_iv=b"\x22" * 16,
        plaintext=b"ABC",
        padded_plaintext=b"ABC" + b"\x0d" * 13,
        pad_bytes=b"\x0d" * 13,
        pad_len=13,
    )

    def fake_encrypt_workflow(**kwargs):
        captured_calls.append(kwargs)
        return dummy

    monkeypatch.setattr(evm, "encrypt_workflow", fake_encrypt_workflow)
    monkeypatch.setattr(evm, "format_hex_blocks", lambda h, b: h)  # not relevant for forwarding

    vm = evm.EncryptionViewModel()
    vm.encrypt(
        mode="CBC",
        plaintext="ABC",
        input_format="TEXT",
        key_hex="11" * 16,
        iv_hex="22" * 16,
        padding_mode="PKCS7",
    )

    assert len(captured_calls) == 1
    assert captured_calls[0] == {
        "mode": "CBC",
        "plaintext": "ABC",
        "input_format": "TEXT",
        "key_hex": "11" * 16,
        "iv_hex": "22" * 16,
        "padding_mode": "PKCS7",
    }


# decrypt should forward all UI arguments unchanged into decrypt_workflow
def test_decrypt_forwards_arguments_to_decrypt_workflow(monkeypatch):
    captured_calls: list[dict] = []

    dummy = DummyDecryptWorkflowResult(
        plaintext_final=b"HELLO",
        key=b"\x10" * 16,
        used_iv=None,
        raw_decrypted=b"HELLO",
        removed_pad=b"",
    )

    def fake_decrypt_workflow(**kwargs):
        captured_calls.append(kwargs)
        return dummy

    monkeypatch.setattr(evm, "decrypt_workflow", fake_decrypt_workflow)
    monkeypatch.setattr(evm, "format_hex_blocks", lambda h, b: h)  # not relevant for forwarding

    vm = evm.EncryptionViewModel()
    vm.decrypt(
        mode="ECB",
        ciphertext_hex="aa" * 16,
        key_hex="10" * 16,
        iv_hex=None,
        unpadding_mode="NONE",
    )

    assert len(captured_calls) == 1
    assert captured_calls[0] == {
        "mode": "ECB",
        "ciphertext_hex": "aa" * 16,
        "key_hex": "10" * 16,
        "iv_hex": None,
        "unpadding_mode": "NONE",
    }

# encrypt should not call format_hex_blocks when workflow fails
def test_encrypt_error_does_not_call_format_hex_blocks(monkeypatch):
    called = {"n": 0}

    def fake_format_hex_blocks(h: str, b: int) -> str:
        called["n"] += 1
        return "SHOULD_NOT_BE_USED"

    monkeypatch.setattr(evm, "format_hex_blocks", fake_format_hex_blocks)

    def fake_encrypt_workflow(**kwargs):
        raise DummyWorkflowError(code="X", field="f", message="m", details="d")

    monkeypatch.setattr(evm, "encrypt_workflow", fake_encrypt_workflow)

    vm = evm.EncryptionViewModel()
    r = vm.encrypt("ECB", "AA", "HEX", "00" * 16, None, "PKCS7")

    assert r.ok is False
    assert called["n"] == 0
