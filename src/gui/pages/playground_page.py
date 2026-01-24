from __future__ import annotations  # needed so type hints can reference classes that are defined later (avoids forward-reference issues)

from PySide6.QtCore import Qt, QSignalBlocker, QTimer  # needed for Qt constants, blocking signals during programmatic UI updates, and scheduling UI work after layout
from PySide6.QtGui import QFont  # needed to set a monospace font for HEX/BIN displays
from PySide6.QtWidgets import (  # needed to build the full Playground UI (inputs, buttons, split panels, dialogs)
    QApplication,   # needed for clipboard access (copy/paste payload)
    QWidget,        # base widget for the page
    QVBoxLayout,    # main vertical stacking layout
    QHBoxLayout,    # horizontal rows (toggle rows, button rows)
    QLabel,         # small descriptive texts and section hints
    QPlainTextEdit, # multiline plain text inputs (plaintext, ciphertext)
    QTextEdit,      # rich text output (HTML explanation panels)
    QLineEdit,      # single-line inputs (key, IV/counter)
    QPushButton,    # clickable actions (Encrypt, Decrypt, Generate, Copy, Paste)
    QGroupBox,      # visual grouping with title + border (Inputs, Results, Key setup, etc...)
    QSplitter,      # resizable left/right panels (Inputs vs Results)
    QButtonGroup,   # makes toggle buttons exclusive (only one selected at a time)
    QToolButton,    # toggle-style buttons (ECB/CBC/CTR, view selection, padding selection)
    QMessageBox,    # success/error dialogs with optional detailed text
)

from src.viewmodels.encryption_viewmodel import EncryptionViewModel  # needed for MVVM: UI calls the viewmodel for encrypt/decrypt/key/iv generation
from src.domain.padding_types import PaddingMode  # needed for type safety of padding/unpadding values (NONE, PKCS7, X923, ISO/IEC 7816-4)

from src.utils.hex_formatting import normalize_hex  # needed to normalize HEX input for clipboard and parsing (ignores spaces/newlines/0x)
from src.utils.hex_converter import bytes_from_hex  # needed to convert HEX text to raw bytes (used for BIN conversion)
from src.utils.bin_formatting import bin_tokens  # needed to format bytes as 8-bit binary tokens

# =========================
# Color palette
# =========================
BLUE = "#2f80ed"         # used for primary theme (selected toggles, main buttons)
BLUE_HOVER = "#256bd6"   # used when hovering primary buttons
BLUE_PRESSED = "#1f5bb8" # used when pressing primary buttons

DANGER = "#D2042D"         # used for destructive actions (Clear)
DANGER_HOVER = "#be123c"   # used for hover on destructive buttons and as padding highlight color
DANGER_PRESSED = "#9f1239" # used when pressing destructive buttons

PANEL_BG = "#eef5ff"       # used as background for group boxes (light blue panel)
PANEL_BORDER = "#c7d7f2"   # used as border color for group boxes
TITLE_BG = "#ffffff"       # used as background for group box titles
TEXT_HINT = "#334155"      # used for helper text labels (hints above inputs)
TEXT_DARK = "#0f172a"      # used for strong titles and important labels

SYSTEM_GREEN = "#16a34a"   # used for system "(none)" messages in HTML panels (so empty states still look intentional)

SETUP_BOX_MIN_HEIGHT = 180  # keeps Key setup and IV/Counter setup aligned in height

# ===========================
# Clipboard payload protocol
# ===========================
CLIPBOARD_HEADER = "MODIVIS_PAYLOAD"  # used to recognize copied payload content
CLIPBOARD_MAX_CHARS = 200_000        # safety limit to avoid freezing UI when clipboard contains huge text

# =========================
# Empty placeholders
# =========================
# These HTML snippets are shown in the right panel before Encrypt/Decrypt is executed.

EMPTY_PADDING_ENCRYPT_HTML = """
<div style="color:#6b7280; font-family:Consolas; font-size:12px; line-height:1.35;">
  Padding explanation will appear here after you click <b>Encrypt</b>.<br>
  (CTR mode does not use padding)
</div>
"""

EMPTY_PADDING_DECRYPT_HTML = """
<div style="color:#6b7280; font-family:Consolas; font-size:12px; line-height:1.35;">
  Unpadding explanation will appear here after you click <b>Decrypt</b>.<br>
  (CTR mode does not use unpadding)
</div>
"""

EMPTY_DATA_ENCRYPT_HTML = """
<div style="color:#6b7280; font-family:Consolas; font-size:12px; line-height:1.35;">
  - Ciphertext (HEX)<br>
  - Key (HEX)<br>
  - IV/Counter (for CBC and CTR)<br>
  - Plaintext byte(s) (input)<br>
  - Padded plaintext byte(s) (for ECB and CBC)
</div>
"""

EMPTY_DATA_DECRYPT_HTML = """
<div style="color:#6b7280; font-family:Consolas; font-size:12px; line-height:1.35;">
  - Ciphertext used (HEX)<br>
  - Key (HEX)<br>
  - IV/Counter (CBC/CTR)<br>
  - Decrypted byte(s) before unpadding (ECB/CBC)<br>
  - Plaintext after unpadding + UTF-8 text (if possible)
</div>
"""

# =========================
# Disabled look helper
# =========================
# This striped gradient is used in QSS for disabled buttons to make "disabled" visually obvious.

DISABLED_STRIPES_BG = """
qlineargradient(
    x1:0, y1:0, x2:1, y2:1,
    stop:0.00 #f4f4f4, stop:0.06 #f4f4f4,
    stop:0.06 #e6e6e6, stop:0.12 #e6e6e6,
    stop:0.12 #f4f4f4, stop:0.18 #f4f4f4,
    stop:0.18 #e6e6e6, stop:0.24 #e6e6e6,
    stop:0.24 #f4f4f4, stop:0.30 #f4f4f4,
    stop:0.30 #e6e6e6, stop:0.36 #e6e6e6,
    stop:0.36 #f4f4f4, stop:0.42 #f4f4f4,
    stop:0.42 #e6e6e6, stop:0.48 #e6e6e6,
    stop:0.48 #f4f4f4, stop:0.54 #f4f4f4,
    stop:0.54 #e6e6e6, stop:0.60 #e6e6e6,
    stop:0.60 #f4f4f4, stop:0.66 #f4f4f4,
    stop:0.66 #e6e6e6, stop:0.72 #e6e6e6,
    stop:0.72 #f4f4f4, stop:0.78 #f4f4f4,
    stop:0.78 #e6e6e6, stop:0.84 #e6e6e6,
    stop:0.84 #f4f4f4, stop:0.90 #f4f4f4,
    stop:0.90 #e6e6e6, stop:1.00 #e6e6e6
)
"""

# =========================
# QSS: Group box styling
# =========================
# Applied at page level (self.setStyleSheet) so all QGroupBox widgets share the same look.

GROUPBOX_QSS = f"""
QGroupBox {{
    background: {PANEL_BG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 10px;
    margin-top: 14px;
    padding: 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    top: 6px;
    padding: 2px 10px;
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    background: {TITLE_BG};
    font-weight: 700;
}}
"""

# ====================================
# QSS: Toggle buttons (Mode and View)
# ====================================
# Used for larger toggles like ECB/CBC/CTR and Encrypt View/Decrypt View.

TOGGLE_QSS = f"""
QToolButton {{
    padding: 6px 12px;
    border: 1px solid #b8b8b8;
    border-radius: 8px;
    background: transparent;
}}
QToolButton:checked {{
    background: {BLUE};
    color: white;
    border: 1px solid {BLUE};
    font-weight: 700;
}}
QToolButton:disabled {{
    color: #7a7a7a;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""

# =============================================================
# QSS: Small toggle buttons (Input format, padding selection)
# =============================================================
# Same behavior as TOGGLE_QSS but smaller padding so it fits more buttons in one row.

SMALL_TOGGLE_QSS = f"""
QToolButton {{
    padding: 4px 10px;
    border: 1px solid #b8b8b8;
    border-radius: 8px;
    background: transparent;
}}
QToolButton:checked {{
    background: {BLUE};
    color: white;
    border: 1px solid {BLUE};
    font-weight: 700;
}}
QToolButton:disabled {{
    color: #7a7a7a;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""

# =============================================================
# QSS: Primary buttons (Encrypt, Decrypt, Copy, Paste)
# =============================================================
# This is the main action style, consistent sizing and strong contrast.

PRIMARY_BTN_QSS = f"""
QPushButton {{
    padding: 10px 18px;
    border-radius: 10px;
    border: 1px solid {BLUE};
    background: {BLUE};
    color: white;
    font-weight: 700;
    min-width: 150px;
}}
QPushButton:hover {{
    background: {BLUE_HOVER};
    border-color: {BLUE_HOVER};
}}
QPushButton:pressed {{
    background: {BLUE_PRESSED};
    border-color: {BLUE_PRESSED};
}}
QPushButton:disabled {{
    color: #6b7280;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""

# ===========================
# QSS: Danger button (Clear)
# ===========================
# Clear is destructive, so it uses a red theme and stays visually distinct.

DANGER_BTN_QSS = f"""
QPushButton {{
    padding: 10px 18px;
    border-radius: 10px;
    border: 1px solid {DANGER};
    background: {DANGER};
    color: white;
    font-weight: 700;
    min-width: 150px;
}}
QPushButton:hover {{
    background: {DANGER_HOVER};
    border-color: {DANGER_HOVER};
}}
QPushButton:pressed {{
    background: {DANGER_PRESSED};
    border-color: {DANGER_PRESSED};
}}
QPushButton:disabled {{
    color: #6b7280;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""

# ======================================================
# QSS: Small primary buttons (Generate Key, Generate IV)
# ======================================================
# Same theme as PRIMARY_BTN_QSS but slightly smaller so it fits inside compact rows.

SMALL_PRIMARY_BTN_QSS = f"""
QPushButton {{
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid {BLUE};
    background: {BLUE};
    color: white;
    font-weight: 700;
    min-width: 120px;
}}
QPushButton:hover {{
    background: {BLUE_HOVER};
    border-color: {BLUE_HOVER};
}}
QPushButton:pressed {{
    background: {BLUE_PRESSED};
    border-color: {BLUE_PRESSED};
}}
QPushButton:disabled {{
    color: #6b7280;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""


class PlaygroundPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.vm = EncryptionViewModel()

        # dirty means inputs changed since last successful run
        self._encrypt_dirty = True
        self._decrypt_dirty = True

        # cache last successful HTML per view (so switching views restores the correct panel)
        self._encrypt_pad_html = ""
        self._encrypt_data_html = ""
        self._decrypt_pad_html = ""
        self._decrypt_data_html = ""

        self._build_ui()
        self._wire()

        # default view = encrypt
        self.btn_view_encrypt.setChecked(True)
        self._apply_view_mode()

        # last successful results (used for clipboard copy)
        self._last_encrypt_res = None
        self._last_decrypt_res = None


    @staticmethod
    def _render_tokens_html(tokens: list[str], color_fn, bytes_per_line: int = 16) -> str:
        lines: list[str] = []
        for i in range(0, len(tokens), bytes_per_line):
            chunk = tokens[i : i + bytes_per_line]
            parts: list[str] = []
            for j, tok in enumerate(chunk, start=i):
                col = color_fn(j)
                if col:
                    parts.append(f"<span style='color:{col}; font-weight:700;'>{tok}</span>")
                else:
                    parts.append(tok)
            lines.append(" ".join(parts))
        return "<br>".join(lines)

    @staticmethod
    def _escape_html(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def _sys_none_html(self, msg: str) -> str:
        safe = self._escape_html(msg)
        return (
            f"<span style='color:{SYSTEM_GREEN}; font-weight:800;'>(none)</span> "
            f"<span style='color:{SYSTEM_GREEN}; font-style:italic;'>"
            f"- system message: {safe}"
            f"</span>"
        )

    def _html_or_sys_none(self, html: str, msg: str) -> str:
        return html if (html or "").strip() else self._sys_none_html(msg)

    def _tokens_or_sys_none(self, tokens: list[str], color_fn, msg: str, bytes_per_line: int = 16) -> str:
        dump = self._render_tokens_html(tokens or [], color_fn, bytes_per_line)
        return self._html_or_sys_none(dump, msg)


    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(12)

        self.setStyleSheet(GROUPBOX_QSS)

        title = QLabel("Playground")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-weight:900; font-size:18px; color:{TEXT_DARK};")
        outer.addWidget(title)

        info = QLabel(
            "<div style='text-align:center;'>"
            "Use this playground to encrypt or decrypt small inputs and inspect the steps. "
            "It is designed for hands-on practice with modes, padding, and HEX/BIN formats."
            "</div>"
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color:{TEXT_HINT}; background:{TITLE_BG}; border:1px solid {PANEL_BORDER}; border-radius:10px; padding:10px;"
        )
        outer.addWidget(info)

        # Mode row
        mode_header = QHBoxLayout()
        mode_header.setSpacing(10)
        mode_header.addStretch(1)

        mode_block = QHBoxLayout()
        mode_block.setSpacing(10)
        mode_block.addWidget(QLabel("Mode:"))

        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)

        self.btn_ecb = self._make_toggle_button("ECB", checked=True)
        self.btn_cbc = self._make_toggle_button("CBC", checked=False)
        self.btn_ctr = self._make_toggle_button("CTR", checked=False)

        self.mode_group.addButton(self.btn_ecb)
        self.mode_group.addButton(self.btn_cbc)
        self.mode_group.addButton(self.btn_ctr)

        mode_block.addWidget(self.btn_ecb)
        mode_block.addWidget(self.btn_cbc)
        mode_block.addWidget(self.btn_ctr)

        mode_header.addLayout(mode_block)
        mode_header.addStretch(1)
        outer.addLayout(mode_header)

        # View row
        view_header = QHBoxLayout()
        view_header.setSpacing(10)
        view_header.addStretch(1)

        view_block = QHBoxLayout()
        view_block.setSpacing(10)
        view_block.addWidget(QLabel("View:"))

        self.view_group = QButtonGroup(self)
        self.view_group.setExclusive(True)

        self.btn_view_encrypt = self._make_toggle_button("Encrypt View", checked=False)
        self.btn_view_decrypt = self._make_toggle_button("Decrypt View", checked=False)

        self.view_group.addButton(self.btn_view_encrypt)
        self.view_group.addButton(self.btn_view_decrypt)

        view_block.addWidget(self.btn_view_encrypt)
        view_block.addWidget(self.btn_view_decrypt)

        view_header.addLayout(view_block)
        view_header.addStretch(1)
        outer.addLayout(view_header)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(12)
        outer.addWidget(splitter, 1)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)

        # Left
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        inputs_box = QGroupBox("Inputs")
        inputs_layout = QVBoxLayout(inputs_box)
        inputs_layout.setSpacing(5)

        # Plaintext input type (encrypt only)
        self.input_type_box = QGroupBox("Plaintext input type")
        it_layout = QHBoxLayout(self.input_type_box)
        it_layout.setSpacing(8)

        self.input_type_group = QButtonGroup(self)
        self.input_type_group.setExclusive(True)

        self.btn_in_text = self._make_small_toggle_button("Text (UTF-8)", checked=True)
        self.btn_in_hex = self._make_small_toggle_button("HEX", checked=False)
        self.btn_in_bin  = self._make_small_toggle_button("Binary", checked=False)

        self.input_type_group.addButton(self.btn_in_text)
        self.input_type_group.addButton(self.btn_in_hex)
        self.input_type_group.addButton(self.btn_in_bin)

        it_layout.addWidget(self.btn_in_text)
        it_layout.addWidget(self.btn_in_hex)
        it_layout.addWidget(self.btn_in_bin)

        it_layout.addStretch(1)

        # Padding selection (encrypt only)
        self.padding_select_box = QGroupBox("Padding scheme (ECB/CBC only)")
        pad_layout = QHBoxLayout(self.padding_select_box)
        pad_layout.setSpacing(8)

        self.pad_group = QButtonGroup(self)
        self.pad_group.setExclusive(True)

        self.btn_pad_none = self._make_small_toggle_button("NONE", checked=False)
        self.btn_pad_pkcs7 = self._make_small_toggle_button("PKCS#7", checked=True)
        self.btn_pad_x923 = self._make_small_toggle_button("X.923", checked=False)
        self.btn_pad_7816 = self._make_small_toggle_button("ISO/IEC 7816-4", checked=False)

        # Hover help (padding)
        self.btn_pad_none.setToolTip("NONE: No padding is added. ECB/CBC require length to be a multiple of 16 byte(s).")
        self.btn_pad_pkcs7.setToolTip("PKCS#7: Add N byte(s), each byte equals N (e.g., 0x04 0x04 0x04 0x04).")
        self.btn_pad_x923.setToolTip("X.923: Add N-1 byte(s) of 0x00, then the last byte is N.")
        self.btn_pad_7816.setToolTip("ISO/IEC 7816-4: Add 0x80, then 0x00 byte(s) until the block is full.")

        self.pad_group.addButton(self.btn_pad_none)
        self.pad_group.addButton(self.btn_pad_pkcs7)
        self.pad_group.addButton(self.btn_pad_x923)
        self.pad_group.addButton(self.btn_pad_7816)

        pad_layout.addWidget(self.btn_pad_none)
        pad_layout.addWidget(self.btn_pad_pkcs7)
        pad_layout.addWidget(self.btn_pad_x923)
        pad_layout.addWidget(self.btn_pad_7816)
        pad_layout.addStretch(1)

        # Unpadding selection (decrypt only)
        self.unpadding_select_box = QGroupBox("Unpadding scheme (ECB/CBC only)")
        unpad_layout = QHBoxLayout(self.unpadding_select_box)
        unpad_layout.setSpacing(8)

        self.unpad_group = QButtonGroup(self)
        self.unpad_group.setExclusive(True)

        self.btn_unpad_none = self._make_small_toggle_button("NONE", checked=False)
        self.btn_unpad_pkcs7 = self._make_small_toggle_button("PKCS#7", checked=True)
        self.btn_unpad_x923 = self._make_small_toggle_button("X.923", checked=False)
        self.btn_unpad_7816 = self._make_small_toggle_button("ISO/IEC 7816-4", checked=False)

        # Hover help (unpadding)
        self.btn_unpad_none.setToolTip("NONE: No byte(s) are removed after decryption. Output stays as raw decrypted byte(s).")
        self.btn_unpad_pkcs7.setToolTip("PKCS#7: Remove N byte(s) where the last byte value is N (and all N byte(s) match).")
        self.btn_unpad_x923.setToolTip("X.923: Remove N byte(s): last byte gives N, preceding removed byte(s) are 0x00.")
        self.btn_unpad_7816.setToolTip("ISO/IEC 7816-4: Remove from the end until 0x80 is found (zeros in between).")

        self.unpad_group.addButton(self.btn_unpad_none)
        self.unpad_group.addButton(self.btn_unpad_pkcs7)
        self.unpad_group.addButton(self.btn_unpad_x923)
        self.unpad_group.addButton(self.btn_unpad_7816)

        unpad_layout.addWidget(self.btn_unpad_none)
        unpad_layout.addWidget(self.btn_unpad_pkcs7)
        unpad_layout.addWidget(self.btn_unpad_x923)
        unpad_layout.addWidget(self.btn_unpad_7816)
        unpad_layout.addStretch(1)

        # Encrypt plaintext
        self.plaintext_hint = QLabel("Write text to encrypt.")
        self.plaintext_hint.setStyleSheet(f"color:{TEXT_HINT};")
        self.plaintext_edit = QPlainTextEdit()
        self.plaintext_edit.setPlaceholderText("Plaintext is the message you want to encrypt.")
        self.plaintext_edit.setMinimumHeight(100)

        self.plaintext_block = QWidget()
        plaintext_layout = QVBoxLayout(self.plaintext_block)
        plaintext_layout.setContentsMargins(0, 0, 0, 0)
        plaintext_layout.setSpacing(6)
        plaintext_layout.addWidget(self.plaintext_hint)
        plaintext_layout.addWidget(self.plaintext_edit)

        # Decrypt ciphertext
        self.ciphertext_hint = QLabel("Paste ciphertext as HEX. Spaces between 16-byte block(s) are allowed (they will be ignored).")
        self.ciphertext_hint.setStyleSheet(f"color:{TEXT_HINT};")
        self.ciphertext_edit = QPlainTextEdit()
        self.ciphertext_edit.setPlaceholderText(
            "Ciphertext is the encrypted HEX you want to decrypt."
        )
        self.ciphertext_edit.setMinimumHeight(120)
        self.ciphertext_edit.setFont(mono)

        self.ciphertext_block = QWidget()
        ciphertext_layout = QVBoxLayout(self.ciphertext_block)
        ciphertext_layout.setContentsMargins(0, 0, 0, 0)
        ciphertext_layout.setSpacing(6)
        ciphertext_layout.addWidget(self.ciphertext_hint)
        ciphertext_layout.addWidget(self.ciphertext_edit)

        # Key (manual HEX) widgets
        self.key_label = QLabel("Provide a key as HEX. You may also generate one below.")
        self.key_label.setStyleSheet(f"color:{TEXT_HINT};")

        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("Key is the secret value that controls AES encryption and decryption.")
        self.key_edit.setFont(mono)

        # Key setup (manual + generator)
        self.key_gen_box = QGroupBox("Key setup")
        self.key_gen_box.setMinimumHeight(SETUP_BOX_MIN_HEIGHT)
        key_gen_layout = QVBoxLayout(self.key_gen_box)
        key_gen_layout.setSpacing(8)

        # Manual input block (label + input)
        key_gen_layout.addWidget(self.key_label)
        key_gen_layout.addWidget(self.key_edit)

        # OR separator
        self.key_or_label = QLabel("OR")
        self.key_or_label.setAlignment(Qt.AlignCenter)
        self.key_or_label.setStyleSheet("color:#64748b; font-weight:800; margin:6px 0;")
        key_gen_layout.addWidget(self.key_or_label)

        # Generation block (size toggles + button)
        self.key_generate_wrap = QWidget()
        gen_wrap_layout = QVBoxLayout(self.key_generate_wrap)
        gen_wrap_layout.setContentsMargins(0, 0, 0, 0)
        gen_wrap_layout.setSpacing(8)

        key_size_line = QHBoxLayout()
        key_size_line.setSpacing(8)
        self.key_size_label = QLabel("Key size for generation:")
        key_size_line.addWidget(self.key_size_label)

        self.key_size_group = QButtonGroup(self)
        self.key_size_group.setExclusive(True)

        self.btn_k128 = self._make_small_toggle_button("AES-128 (16 Bytes)", checked=True)
        self.btn_k192 = self._make_small_toggle_button("AES-192 (24 Bytes)", checked=False)
        self.btn_k256 = self._make_small_toggle_button("AES-256 (32 Bytes)", checked=False)

        self.key_size_group.addButton(self.btn_k128)
        self.key_size_group.addButton(self.btn_k192)
        self.key_size_group.addButton(self.btn_k256)

        key_size_line.addWidget(self.btn_k128)
        key_size_line.addWidget(self.btn_k192)
        key_size_line.addWidget(self.btn_k256)
        key_size_line.addStretch(1)

        # Put button on the same row as the key size toggles
        self.gen_key_btn = QPushButton("Generate Key")
        self.gen_key_btn.setStyleSheet(SMALL_PRIMARY_BTN_QSS)

        key_size_line.addStretch(1)           # pushes the button to the right
        key_size_line.addWidget(self.gen_key_btn)

        gen_wrap_layout.addLayout(key_size_line)


        key_gen_layout.addWidget(self.key_generate_wrap)
        key_gen_layout.addStretch(1)

        # IV / Counter setup (CBC / CTR)
        self.iv_box = QGroupBox("IV / Counter setup (CBC / CTR)")
        self.iv_box.setMinimumHeight(SETUP_BOX_MIN_HEIGHT)
        iv_box_layout = QVBoxLayout(self.iv_box)
        iv_box_layout.setSpacing(8)

        self.iv_hint = QLabel("Provide the IV/Counter as HEX (16 byte(s)). Required for CBC and CTR.")
        self.iv_hint.setStyleSheet(f"color:{TEXT_HINT};")

        self.iv_edit = QLineEdit()
        self.iv_edit.setPlaceholderText("IV is required for CBC and CTR to make encryption non-repeating.")
        self.iv_edit.setFont(mono)

        iv_box_layout.addWidget(self.iv_hint)
        iv_box_layout.addWidget(self.iv_edit)

        # OR label (centered)
        self.iv_or_label = QLabel("OR")
        self.iv_or_label.setAlignment(Qt.AlignCenter)
        self.iv_or_label.setStyleSheet("color:#64748b; font-weight:800; margin:6px 0;")
        iv_box_layout.addWidget(self.iv_or_label)

        # Generate IV centered
        iv_btn_line = QHBoxLayout()
        iv_btn_line.addStretch(1)
        self.gen_iv_btn = QPushButton("Generate IV")
        self.gen_iv_btn.setStyleSheet(SMALL_PRIMARY_BTN_QSS)
        iv_btn_line.addWidget(self.gen_iv_btn)
        iv_btn_line.addStretch(1)
        iv_box_layout.addLayout(iv_btn_line)
        iv_box_layout.addStretch(1)

        # Buttons row
        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(12)

        # Main actions (left side)
        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        self.clear_btn = QPushButton("Clear")

        # Clipboard actions (right side)
        self.copy_clip_btn = QPushButton("Copy results to clipboard")
        self.paste_clip_btn = QPushButton("Paste results from clipboard")

        # Styles (same size look)
        self.encrypt_btn.setStyleSheet(PRIMARY_BTN_QSS)
        self.decrypt_btn.setStyleSheet(PRIMARY_BTN_QSS)
        self.clear_btn.setStyleSheet(DANGER_BTN_QSS)

        # Copy/Paste look like main actions too (same size)
        self.copy_clip_btn.setStyleSheet(PRIMARY_BTN_QSS)
        self.paste_clip_btn.setStyleSheet(PRIMARY_BTN_QSS)

        # enforce same height everywhere
        for b in (self.encrypt_btn, self.decrypt_btn, self.clear_btn, self.copy_clip_btn, self.paste_clip_btn):
            b.setMinimumHeight(40)

        self.encrypt_btn.setDefault(True)
        self.encrypt_btn.setAutoDefault(True)

        # left group
        left_actions = QHBoxLayout()
        left_actions.setSpacing(12)
        left_actions.addWidget(self.encrypt_btn)
        left_actions.addWidget(self.decrypt_btn)
        left_actions.addWidget(self.clear_btn)

        # right group
        right_actions = QHBoxLayout()
        right_actions.setSpacing(12)
        right_actions.addWidget(self.copy_clip_btn)
        right_actions.addWidget(self.paste_clip_btn)

        # Assemble row
        buttons_row.addLayout(left_actions)
        buttons_row.addStretch(1)
        buttons_row.addLayout(right_actions)

        # Assemble inputs
        inputs_layout.addWidget(self.input_type_box)
        inputs_layout.addWidget(self.padding_select_box)
        inputs_layout.addWidget(self.unpadding_select_box)

        inputs_layout.addWidget(self.plaintext_block)
        inputs_layout.addWidget(self.ciphertext_block)

        # Key setup
        inputs_layout.addWidget(self.key_gen_box)

        # IV box (CBC/CTR) in both views
        inputs_layout.addWidget(self.iv_box)

        # Leave a small gap between the IV/Counter box and the buttons row
        inputs_layout.addSpacing(10)
        inputs_layout.addLayout(buttons_row)
        left_layout.addWidget(inputs_box, 1)

        # Right
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        results_box = QGroupBox("Results in HEX")
        results_layout = QVBoxLayout(results_box)
        results_layout.setSpacing(8)

        self.padding_box = QGroupBox("Padding - ECB/CBC only")
        padding_layout = QVBoxLayout(self.padding_box)
        padding_layout.setSpacing(6)

        self.padding_view = QTextEdit()
        self.padding_view.setReadOnly(True)
        self.padding_view.setFont(mono)
        self.padding_view.setMinimumHeight(240)
        self.padding_view.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

        # show wrapped default hint
        self.padding_view.setHtml(EMPTY_PADDING_ENCRYPT_HTML)

        padding_layout.addWidget(self.padding_view)
        results_layout.addWidget(self.padding_box)

        self.data_box = QGroupBox("Encryption Data")
        data_layout = QVBoxLayout(self.data_box)
        data_layout.setSpacing(6)

        self.data_view = QTextEdit()
        self.data_view.setReadOnly(True)
        self.data_view.setFont(mono)
        self.data_view.setMinimumHeight(320)
        self.data_view.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

        # show wrapped default hint
        self.data_view.setHtml(EMPTY_DATA_ENCRYPT_HTML)

        data_layout.addWidget(self.data_view)
        results_layout.addWidget(self.data_box)

        right_layout.addWidget(results_box, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)

        # make Results not start too small
        right.setMinimumWidth(520)

        # keep resizing behavior reasonable
        splitter.setStretchFactor(0, 3)  # Inputs
        splitter.setStretchFactor(1, 2)  # Results

        # force a nicer default split after layout is ready
        def _init_split():
            w = splitter.width() or 1200
            splitter.setSizes([int(w * 0.70), int(w * 0.30)])

        QTimer.singleShot(0, _init_split)

    def _make_toggle_button(self, text: str, checked: bool) -> QToolButton:
        btn = QToolButton()
        btn.setText(text)
        btn.setCheckable(True)
        btn.setChecked(checked)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(TOGGLE_QSS)
        return btn

    def _make_small_toggle_button(self, text: str, checked: bool) -> QToolButton:
        btn = QToolButton()
        btn.setText(text)
        btn.setCheckable(True)
        btn.setChecked(checked)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(SMALL_TOGGLE_QSS)
        return btn


    def _wire(self) -> None:
        self.mode_group.buttonToggled.connect(lambda *_: self._on_mode_changed())
        self.view_group.buttonToggled.connect(lambda *_: self._apply_view_mode())

        self.input_type_group.buttonToggled.connect(lambda *_: self._on_input_type_changed())
        self.pad_group.buttonToggled.connect(lambda *_: self._on_padding_changed())
        self.unpad_group.buttonToggled.connect(lambda *_: self._on_unpadding_changed())

        self.key_edit.textChanged.connect(lambda *_: self._mark_encrypt_dirty_and_decrypt_dirty())
        self.iv_edit.textChanged.connect(lambda *_: self._mark_encrypt_dirty_and_decrypt_dirty())
        self.plaintext_edit.textChanged.connect(lambda *_: self._mark_encrypt_dirty())
        self.ciphertext_edit.textChanged.connect(lambda *_: self._mark_decrypt_dirty())

        self.key_size_group.buttonToggled.connect(lambda *_: self._mark_encrypt_dirty())

        self.gen_key_btn.clicked.connect(self._on_generate_key)
        self.gen_iv_btn.clicked.connect(self._on_generate_iv)

        self.encrypt_btn.clicked.connect(self._on_encrypt)
        self.decrypt_btn.clicked.connect(self._on_decrypt)
        self.clear_btn.clicked.connect(self._on_clear)

        self.copy_clip_btn.clicked.connect(self._on_copy_to_clipboard)
        self.paste_clip_btn.clicked.connect(self._on_paste_from_clipboard)


    def _current_mode(self) -> str:
        if self.btn_ecb.isChecked():
            return "ECB"
        if self.btn_cbc.isChecked():
            return "CBC"
        return "CTR"

    def _is_encrypt_view(self) -> bool:
        return self.btn_view_encrypt.isChecked()

    def _current_key_bits(self) -> int:
        if self.btn_k192.isChecked():
            return 192
        if self.btn_k256.isChecked():
            return 256
        return 128

    def _current_input_format(self) -> str:
        if self.btn_in_hex.isChecked():
            return "HEX"
        if self.btn_in_bin.isChecked():        
            return "BIN"                         
        return "TEXT"

    def _current_padding_mode(self) -> PaddingMode:
        if self.btn_pad_none.isChecked():
            return "NONE"
        if self.btn_pad_x923.isChecked():
            return "X923"
        if self.btn_pad_7816.isChecked():
            return "ISO/IEC 7816-4"
        return "PKCS7"

    def _current_unpadding_mode(self) -> PaddingMode:
        if self.btn_unpad_none.isChecked():
            return "NONE"
        if self.btn_unpad_x923.isChecked():
            return "X923"
        if self.btn_unpad_7816.isChecked():
            return "ISO/IEC 7816-4"
        return "PKCS7"

    def _sync_mode_rules(self) -> None:
        mode = self._current_mode()
        encrypt_view = self._is_encrypt_view()

        needs_iv = mode in ("CBC", "CTR")
        self.iv_edit.setEnabled(needs_iv)
        self.iv_hint.setEnabled(needs_iv)
        self.gen_iv_btn.setEnabled(needs_iv)

        is_block_mode = mode in ("ECB", "CBC")
        self.padding_select_box.setEnabled(is_block_mode)
        self.unpadding_select_box.setEnabled(is_block_mode)

        if mode == "CTR":
            # force NONE Padding for CTR
            self.btn_pad_none.setChecked(True)
            self.btn_unpad_none.setChecked(True)

        # show correct boxes per view
        self.input_type_box.setVisible(encrypt_view)
        self.padding_select_box.setVisible(encrypt_view)
        self.unpadding_select_box.setVisible(not encrypt_view)


    def _clear_right_panel(self) -> None:
        if self._is_encrypt_view():
            self.padding_view.setHtml(EMPTY_PADDING_ENCRYPT_HTML)
            self.data_view.setHtml(EMPTY_DATA_ENCRYPT_HTML)
        else:
            self.padding_view.setHtml(EMPTY_PADDING_DECRYPT_HTML)
            self.data_view.setHtml(EMPTY_DATA_DECRYPT_HTML)

    def _mark_encrypt_dirty(self) -> None:
        self._encrypt_dirty = True
        if self._is_encrypt_view():
            self._clear_right_panel()

    def _mark_decrypt_dirty(self) -> None:
        self._decrypt_dirty = True
        if not self._is_encrypt_view():
            self._clear_right_panel()

    def _mark_encrypt_dirty_and_decrypt_dirty(self) -> None:
        self._mark_encrypt_dirty()
        self._mark_decrypt_dirty()

    def _on_mode_changed(self) -> None:
        self._sync_mode_rules()
        self._mark_encrypt_dirty_and_decrypt_dirty()

    def _on_input_type_changed(self) -> None:
        fmt = self._current_input_format()
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)

        if fmt == "HEX":
            self.plaintext_edit.setFont(mono)
            self.plaintext_edit.setPlaceholderText(
                "HEX input: paste byte(s) as HEX.\n"
                "Spaces/newlines/0x-Prefix are allowed.\n"
                "Example: 41 42 43 or 0x414243"
            )
            self.plaintext_hint.setText("Plaintext is provided as HEX byte(s) (not human text).")

        elif fmt == "BIN":
            self.plaintext_edit.setFont(mono)
            self.plaintext_edit.setPlaceholderText(
                "Binary input: paste bit(s) using 0 and 1.\n"
                "Spaces/newlines/0b-Prefix are allowed.\n"
                "Example: 01000001 01000010 01000011"
            )
            self.plaintext_hint.setText("Plaintext is provided as binary bit(s) (not human text).")

        else:
            self.plaintext_edit.setFont(QFont())
            self.plaintext_edit.setPlaceholderText("Write the message you want to protect with encryption.")
            self.plaintext_hint.setText("Plaintext is the message you want to encrypt.")

        QTimer.singleShot(0, self.plaintext_edit.viewport().update)
        self._mark_encrypt_dirty()

    def _on_padding_changed(self) -> None:
        self._mark_encrypt_dirty()

    def _on_unpadding_changed(self) -> None:
        self._mark_decrypt_dirty()


    def _ask_allow_autogen(self, title: str, msg: str) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        return box.exec() == QMessageBox.Yes
        
    def _make_details_area_scrollable(self, box: QMessageBox) -> None:
        te = box.findChild(QTextEdit)
        if not te:
            return

        # wrap long lines so scrolling is vertical
        te.setLineWrapMode(QTextEdit.WidgetWidth)

        # vertical scroll when needed
        te.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # avoid horizontal scrolling
        te.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # keep a fixed visible area so large content must scroll
        te.setMinimumWidth(900)
        te.setMaximumHeight(300)
        te.setMinimumHeight(220)

    def _show_error(self, summary: str, technical: str = "") -> None:
        box = QMessageBox(self)
        box.setOption(QMessageBox.DontUseNativeDialog, True)
        box.setSizeGripEnabled(True)

        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Error")
        box.setText(summary)

        if technical and technical != summary:
            box.setDetailedText(technical)

        box.resize(820, 520)
        box.setMinimumWidth(760)

        self._make_details_area_scrollable(box)
        box.exec()

    def _show_success(self, summary: str, details: str = "") -> None:
        box = QMessageBox(self)
        box.setOption(QMessageBox.DontUseNativeDialog, True)
        box.setSizeGripEnabled(True)

        box.setIcon(QMessageBox.Information)
        box.setWindowTitle("Success")
        box.setText(summary)

        if details:
            box.setDetailedText(details)

        box.resize(820, 520)
        box.setMinimumWidth(760)

        self._make_details_area_scrollable(box)
        box.exec()


    def _apply_view_mode(self) -> None:
        encrypt_view = self._is_encrypt_view()

        self.plaintext_block.setVisible(encrypt_view)
        self.encrypt_btn.setVisible(encrypt_view)

        self.ciphertext_block.setVisible(not encrypt_view)
        self.decrypt_btn.setVisible(not encrypt_view)

        # always show key manual input box in both views
        self.key_gen_box.setVisible(True)

        # only show generator part + OR in Encrypt view
        self.key_or_label.setVisible(encrypt_view)
        self.key_generate_wrap.setVisible(encrypt_view)

        # IV box visible in both views and generate button only in Encrypt view
        self.iv_box.setVisible(True)
        self.gen_iv_btn.setVisible(encrypt_view)
        self.iv_or_label.setVisible(encrypt_view)

        if encrypt_view:
            self.key_label.setText("Provide a key as HEX. You may also generate one below.")
            self.key_edit.setPlaceholderText("Key is the secret value that controls AES encryption and decryption.")
            self.padding_box.setTitle("Padding - ECB/CBC only")
            self.data_box.setTitle("Encryption Data")
        else:
            self.key_label.setText("Provide the key as HEX. Decryption cannot guess the key.")
            self.key_edit.setPlaceholderText("Key must be the same secret value that was used during encryption.")
            self.padding_box.setTitle("Unpadding - ECB/CBC only")
            self.data_box.setTitle("Decryption Data")

        self._sync_mode_rules()

        # restore last successful results for this view (if not dirty)
        if encrypt_view:
            if not self._encrypt_dirty and self._encrypt_pad_html and self._encrypt_data_html:
                self.padding_view.setHtml(self._encrypt_pad_html)
                self.data_view.setHtml(self._encrypt_data_html)
            else:
                self._clear_right_panel()
        else:
            if not self._decrypt_dirty and self._decrypt_pad_html and self._decrypt_data_html:
                self.padding_view.setHtml(self._decrypt_pad_html)
                self.data_view.setHtml(self._decrypt_data_html)
            else:
                self._clear_right_panel()


    def _on_generate_key(self) -> None:
        if not self._is_encrypt_view():
            return
        try:
            bits = self._current_key_bits()
            key_hex = self.vm.generate_key_hex(bits)
            with QSignalBlocker(self.key_edit):
                self.key_edit.setText(key_hex)
            self._show_success(f"AES-{bits} key generated.", f"Key (HEX): {key_hex}")
        except Exception as e:
            self._show_error("Key generation failed.", str(e))

    def _on_generate_iv(self) -> None:
        if not self._is_encrypt_view():
            return
        try:
            if not self.iv_edit.isEnabled():
                self._show_error("IV is not used in ECB mode.", "")
                return
            iv_hex = self.vm.generate_iv_hex()
            with QSignalBlocker(self.iv_edit):
                self.iv_edit.setText(iv_hex)
            self._show_success("IV generated.", f"IV/Counter (HEX): {iv_hex}")
        except Exception as e:
            self._show_error("IV generation failed.", str(e))


    def _ensure_key_or_confirm_autogen_encrypt(self) -> bool:
        if self.key_edit.text().strip():
            return True
        bits = self._current_key_bits()
        allow = self._ask_allow_autogen(
            "Key is missing",
            f"The key field is empty.\n\nDo you want to generate an AES-{bits} key now?",
        )
        if not allow:
            return False
        key_hex = self.vm.generate_key_hex(bits)
        with QSignalBlocker(self.key_edit):
            self.key_edit.setText(key_hex)
        return True

    def _ensure_iv_or_confirm_autogen_encrypt(self) -> bool:
        if not self.iv_edit.isEnabled():
            return True
        if self.iv_edit.text().strip():
            return True
        mode = self._current_mode()
        allow = self._ask_allow_autogen(
            "IV is missing",
            f"The IV/Counter field is empty.\n\nDo you want to generate an IV/Counter for {mode} now?",
        )
        if not allow:
            return False
        iv_hex = self.vm.generate_iv_hex()
        with QSignalBlocker(self.iv_edit):
            self.iv_edit.setText(iv_hex)
        return True


    @staticmethod
    def _build_payload(lines: dict[str, str]) -> str:
        ordered = ["target", "mode", "ciphertext_hex", "plaintext_hex", "plaintext_bin", "key_hex", "iv_hex", "padding_mode", "unpadding_mode", "input_format"]
        out: list[str] = [CLIPBOARD_HEADER]
        for k in ordered:
            if k in lines and lines[k] != "":
                out.append(f"{k}={lines[k]}")
        for k in sorted(lines.keys()):
            if k not in ordered and lines[k] != "":
                out.append(f"{k}={lines[k]}")
        return "\n".join(out).strip() + "\n"

    @staticmethod
    def _parse_payload(raw: str) -> dict[str, str] | None:
        if not raw:
            return None
        raw = raw.strip()
        if not raw.startswith(CLIPBOARD_HEADER):
            return None

        payload: dict[str, str] = {}
        for line in raw.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            payload[k.strip().lower()] = v.strip()
        return payload

    @staticmethod
    def _norm_hex_for_clipboard(s: str) -> str:
        return normalize_hex(
            s,
            label="Clipboard HEX",
            purpose="PlaygroundPage._norm_hex_for_clipboard",
        ).lower()

    @staticmethod
    def _hex_to_bin_groups(hex_text: str) -> str:
        clean = normalize_hex(
            hex_text,
            label="Clipboard HEX",
            purpose="PlaygroundPage._hex_to_bin_groups",
        )
        if clean == "":
            return ""

        data = bytes_from_hex(
            clean,
            label="Clipboard HEX",
            purpose="PlaygroundPage._hex_to_bin_groups",
            assume_clean=True,
        )

        # 1 byte = 8 bits token and spaced like: 01000001 11110000 etc
        return " ".join(
            bin_tokens(
                data,
                label="Clipboard BIN",
                purpose="PlaygroundPage._hex_to_bin_groups",
            )
        )

    def _select_mode_from_string(self, mode: str) -> None:
        m = (mode or "").strip().upper()
        with QSignalBlocker(self.mode_group):
            if m == "CBC":
                self.btn_cbc.setChecked(True)
            elif m == "CTR":
                self.btn_ctr.setChecked(True)
            else:
                self.btn_ecb.setChecked(True)
        self._sync_mode_rules()

    def _set_padding_buttons(self, pad: str) -> None:
        p = (pad or "").strip().upper()
        with QSignalBlocker(self.pad_group):
            if p == "NONE":
                self.btn_pad_none.setChecked(True)
            elif p == "X923":
                self.btn_pad_x923.setChecked(True)
            elif p in ("ISO7816", "ISO/IEC 7816-4", "7816-4"):
                self.btn_pad_7816.setChecked(True)
            else:
                self.btn_pad_pkcs7.setChecked(True)

    def _set_unpadding_buttons(self, unpad: str) -> None:
        p = (unpad or "").strip().upper()
        with QSignalBlocker(self.unpad_group):
            if p == "NONE":
                self.btn_unpad_none.setChecked(True)
            elif p == "X923":
                self.btn_unpad_x923.setChecked(True)
            elif p in ("ISO7816", "ISO/IEC 7816-4", "7816-4"):
                self.btn_unpad_7816.setChecked(True)
            else:
                self.btn_unpad_pkcs7.setChecked(True)

    def _goto_encrypt_view(self) -> None:
        with QSignalBlocker(self.view_group):
            self.btn_view_encrypt.setChecked(True)
        self._apply_view_mode()

    def _goto_decrypt_view(self) -> None:
        with QSignalBlocker(self.view_group):
            self.btn_view_decrypt.setChecked(True)
        self._apply_view_mode()

    def _set_plaintext(self, edit: QPlainTextEdit, value: str) -> None:
        value = (value or "").strip()
        with QSignalBlocker(edit):
            edit.setPlainText(value)

    def _safe_clipboard_text(self) -> str:
        cb = QApplication.clipboard()
        txt = cb.text() or ""
        if len(txt) > CLIPBOARD_MAX_CHARS:
            raise ValueError("Clipboard content is too large.")
        return txt

    def _on_copy_to_clipboard(self) -> None:
        try:
            encrypt_view = self._is_encrypt_view()

            if encrypt_view:
                if self._encrypt_dirty or self._last_encrypt_res is None:
                    self._show_error("There's nothing to copy yet.", "Run Encrypt first to generate an output.")
                    return
                res = self._last_encrypt_res
                mode = self._current_mode()

                payload = {
                    "target": "decrypt",
                    "mode": mode,
                    "ciphertext_hex": self._norm_hex_for_clipboard(res.output_hex),
                    "key_hex": self._norm_hex_for_clipboard(res.used_key_hex),
                }
                if getattr(res, "used_iv_hex", ""):
                    payload["iv_hex"] = self._norm_hex_for_clipboard(res.used_iv_hex)

                if mode in ("ECB", "CBC"):
                    payload["unpadding_mode"] = (res.padding_mode or "PKCS7")

                text = self._build_payload(payload)

            else:
                if self._decrypt_dirty or self._last_decrypt_res is None:
                    self._show_error("There's nothing to copy yet.", "Run Decrypt first to generate an output.")
                    return
                res = self._last_decrypt_res
                mode = self._current_mode()

                # use current input selection as preference (even if hidden in decrypt view)
                fmt = self._current_input_format()
                if fmt == "TEXT":
                    fmt = "HEX"  # TEXT would change bytes and clipboard replay should be raw bytes

                payload = {
                    "target": "encrypt",
                    "mode": mode,
                    "input_format": fmt,
                    "key_hex": self._norm_hex_for_clipboard(res.used_key_hex),
                    # always provide HEX as a safe fallback
                    "plaintext_hex": self._norm_hex_for_clipboard(res.output_hex),
                }


                if fmt == "BIN":
                    payload["plaintext_bin"] = self._hex_to_bin_groups(res.output_hex)

                if getattr(res, "used_iv_hex", ""):
                    payload["iv_hex"] = self._norm_hex_for_clipboard(res.used_iv_hex)

                if mode in ("ECB", "CBC"):
                    payload["padding_mode"] = (res.unpadding_mode or "PKCS7")

                text = self._build_payload(payload)

            QApplication.clipboard().setText(text)
            target_action = payload["target"].capitalize()
            self._show_success("Copied payload to clipboard.", f"MODIVIS payload copied. Paste to {target_action}.")
        except Exception as e:
            self._show_error("Copy to clipboard failed.", str(e))

    def _on_paste_from_clipboard(self) -> None:
        try:
            raw = self._safe_clipboard_text()
            payload = self._parse_payload(raw)
            if payload is None:
                self._show_error(
                    "No MODIVIS payload found in the clipboard.",
                    f"Copy an MODIVIS payload that begins with: {CLIPBOARD_HEADER}",
                )
                return

            target = payload.get("target", "").lower().strip()
            mode = payload.get("mode", "ECB").upper().strip()

            if target == "decrypt":
                self._goto_decrypt_view()
            elif target == "encrypt":
                self._goto_encrypt_view()
            else:
                if payload.get("ciphertext_hex"):
                    self._goto_decrypt_view()
                    target = "decrypt"
                elif payload.get("plaintext_hex") or payload.get("plaintext_bin"):
                    self._goto_encrypt_view()
                    target = "encrypt"
                else:
                    raise ValueError("Payload has no target and no ciphertext/plaintext data.")

            self._select_mode_from_string(mode)

            key_hex = payload.get("key_hex", "")
            iv_hex = payload.get("iv_hex", "")

            if key_hex:
                with QSignalBlocker(self.key_edit):
                    self.key_edit.setText(key_hex)

            if iv_hex and self.iv_edit.isEnabled():
                with QSignalBlocker(self.iv_edit):
                    self.iv_edit.setText(iv_hex)


            if target == "decrypt":
                ct_hex = payload.get("ciphertext_hex", "")
                if not ct_hex:
                    raise ValueError("Decrypt payload is missing ciphertext_hex.")
                self._set_plaintext(self.ciphertext_edit, ct_hex)

                if mode in ("ECB", "CBC") and payload.get("unpadding_mode"):
                    self._set_unpadding_buttons(payload["unpadding_mode"])

                self._mark_decrypt_dirty()
                self._show_success("Pasted from clipboard.", "Decryption inputs updated.")
                return


            pt_hex = payload.get("plaintext_hex", "")
            pt_bin = payload.get("plaintext_bin", "")

            fmt = (payload.get("input_format", "HEX") or "HEX").strip().upper()

            # prefer BIN only if plaintext_bin exists, otherwise fallback to HEX if available
            if fmt == "BIN" and pt_bin:
                pt_value = pt_bin
            else:
                if not pt_hex:
                    raise ValueError("Encrypt payload is missing plaintext_hex.")
                fmt = "HEX"
                pt_value = pt_hex

            with QSignalBlocker(self.input_type_group):
                if fmt == "BIN":
                    self.btn_in_bin.setChecked(True)
                elif fmt == "TEXT":
                    self.btn_in_text.setChecked(True)
                else:
                    self.btn_in_hex.setChecked(True)

            self._on_input_type_changed()
            self._set_plaintext(self.plaintext_edit, pt_value)

            if mode in ("ECB", "CBC") and payload.get("padding_mode"):
                self._set_padding_buttons(payload["padding_mode"])

            self._mark_encrypt_dirty()
            self._show_success("Pasted from clipboard.", "Encryption inputs updated.")

        except Exception as e:
            self._show_error("Paste from clipboard failed.", str(e))


    def _render_padding_encrypt_html(self, mode: str, res) -> str:
        if mode == "CTR":
            return """
            <div style="font-family:Consolas; font-size:12px;">
            <u><b>CTR mode</b></u><br>
            CTR works like a stream, so it can encrypt any length.<br>
            That means: <b>no padding is added</b> and later <b>no unpadding is needed</b>.<br>
            </div>
            """

        pad_mode = res.padding_mode

        data_tokens: list[str] = res.input_tokens or []
        pad_tokens: list[str] = res.pad_tokens or []
        tokens: list[str] = (res.padded_tokens or (data_tokens + pad_tokens))
        pad_start: int = int(res.pad_start_index or len(data_tokens))

        L = len(data_tokens)
        r = (L % 16)
        N = int(res.pad_len or 0)

        # special case: padding NONE in ECB/CBC
        if pad_mode == "NONE":
            dump_same = self._tokens_or_sys_none(
                data_tokens,
                lambda _i: BLUE,
                "Plaintext is empty (0 byte(s))."
            )

            status = (
                f"""
                <u><b>Check</b></u><br>
                - Plaintext length = <b>L</b> byte(s) (here: <b>L = {L}</b>)<br>
                - We check the leftover byte(s) when dividing by 16: <b>L mod 16</b> (here: <b>{L} mod 16 = {r}</b>)<br><br>
                The result is <b>0</b>, the plaintext already fits into 16-byte block(s).
                """
                if r == 0
                else f"""
                <u><b>Check</b></u><br>
                - Plaintext length = <b>L</b> byte(s) (here: <b>L = {L}</b>)<br>
                - We check the leftover byte(s) when dividing by 16: <b>L mod 16</b> (here: <b>{L} mod 16 = {r}</b>)<br><br>
                The result is <b>not 0</b>, the last block would be incomplete.
                """
            )

            return f"""
            <div style="font-family:Consolas; font-size:12px;">
            <u><b>Padding (NONE)</b></u><br>
            You selected <b>NONE</b>, so <b>no padding byte(s) are added</b>.<br>
            ECB/CBC require the plaintext length to be a multiple of 16.<br><br>
            {status}<br><br>

            <u><b>Color Key</b></u><br>
            <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = real data byte(s)<br>
            <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = padding byte(s) (none here)<br>
            <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

            <u><b>Padded plaintext byte(s)</b></u> (same as input)
            <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{dump_same}</pre>
            </div>
            """

        # supported padding schemes (PKCS7 / X923 / ISO/IEC 7816-4)
        def color_fn(idx: int) -> str | None:
            return DANGER_HOVER if idx >= pad_start else BLUE

        dump = self._tokens_or_sys_none(
            tokens,
            color_fn,
            "Plaintext is empty (0 byte(s))."
        )

        if r == 0:
            step3 = (
                "Because <b>r = 0</b> (exact 16-byte boundary), we still set <b>N = 16</b> "
                "and add a full extra block so the padding is always recognizable."
            )
        else:
            step3 = (
                f"Because <b>r &gt; 0</b>, we set <b>N = 16 - r = 16 - {r} = {N}</b> "
                "to fill the last block up to 16 byte(s)."
            )

        if pad_mode == "PKCS7":
            last = (pad_tokens[0] if pad_tokens else "??")
            desc = (
                f"Append <b>N</b> padding byte(s). Each padding byte has the value <b>N</b>. "
                f"Here: <b>N = {N}</b>, so we add <b>{N}</b> byte(s) of <b>0x{last}</b>."
            )
        elif pad_mode == "X923":
            last = (pad_tokens[-1] if pad_tokens else "??")
            desc = (
                f"Append <b>N</b> padding byte(s). The first <b>N-1</b> byte(s) are <b>0x00</b>, "
                f"and the last byte stores <b>N</b>. Here: last byte is <b>0x{last}</b>."
            )
        elif pad_mode == "ISO/IEC 7816-4":
            desc = (
                "Append one byte <b>0x80</b>, then append <b>0x00</b> byte(s) until the block is full."
            )
        else:
            desc = "No padding is used."

        return f"""
        <div style="font-family:Consolas; font-size:12px;">
        <b>Padding ({pad_mode})</b><br><br>
        <u><b>Why padding matters in AES?</b></u><br>
        AES in ECB and CBC modes can encrypt only complete block(s) of 16 byte(s).<br>
        So we add extra byte(s) at the end to make the length a multiple of 16.<br><br>

        <u><b>How do we count?</b></u><br>
        <b>- Step 1:</b> Count plaintext length (L). Here: <b>L = {L}</b> byte(s).<br>
        <b>- Step 2:</b> Compute how many byte(s) are left in the current 16-byte block: r = L mod 16. Here: <b>r = {L} mod 16 = {r}</b>.<br>
        <b>- Step 3:</b> Compute how many byte(s) we must add to reach the next full block. {step3}<br>
        <b>- Step 4:</b> {desc}<br><br>

        <u><b>Color Key</b></u><br>
        <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = real data byte(s)<br>
        <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = added padding byte(s)<br>
        <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

        <u><b>Padded plaintext byte(s)</b></u> (16-byte line(s))
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{dump}</pre>
        </div>
        """

    def _render_padding_decrypt_html(self, mode: str, res) -> str:
        if mode == "CTR":
            return """
            <div style="font-family:Consolas; font-size:12px;">
            <u><b>CTR mode</b></u><br>
            CTR does not use padding, so there is no unpadding step.<br>
            </div>
            """

        unpad_mode = res.unpadding_mode
        pad_len = int(res.removed_pad_len or 0)

        raw_tokens: list[str] = res.decrypted_raw_tokens or []
        removed_tokens: list[str] = res.removed_pad_tokens or []

        pad_start = int(res.removed_pad_start_index or max(0, len(raw_tokens) - pad_len))

        # special case : unpadding NONE in ECB/CBC
        if unpad_mode == "NONE":
            before_dump = self._tokens_or_sys_none(
                raw_tokens,
                lambda _i: BLUE,
                "No decrypted byte(s) to show."
            )
            after_dump = before_dump  # same bytes no change
            removed_dump = self._sys_none_html("No padding byte(s) were removed (unpadding is NONE).")

            return f"""
            <div style="font-family:Consolas; font-size:12px;">
            <u><b>Unpadding (NONE) - ECB/CBC</b></u><br>
            You selected <b>NONE</b>, so <b>no byte(s) are removed</b> after decryption.<br>
            The output stays exactly the raw decrypted byte(s).<br><br>

            <u><b>Color Key</b></u><br>
            <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = byte(s) that stay<br>
            <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = byte(s) removed (none here)<br>
            <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

            <u><b>Byte(s) before unpadding</b></u>
            <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{before_dump}</pre>

            <u><b>Byte(s) after unpadding</b></u>
            <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{after_dump}</pre>

            <u><b>Removed padding byte(s)</b></u>
            <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{removed_dump}</pre>
            </div>
            """

        # suported unpadding schemes (PKCS7 / X923 / ISO/IEC 7816-4)
        def color_before(idx: int) -> str | None:
            return DANGER_HOVER if (pad_len > 0 and idx >= pad_start) else BLUE

        before_dump = self._tokens_or_sys_none(
            raw_tokens,
            color_before,
            "No decrypted byte(s) to show."
        )

        out_tokens: list[str] = res.output_tokens or []
        after_dump = self._tokens_or_sys_none(
            out_tokens,
            lambda _i: BLUE,
            "No byte(s) remain after unpadding (plaintext length is 0 byte(s))."
        )

        removed_dump = self._tokens_or_sys_none(
            removed_tokens,
            lambda _i: DANGER_HOVER,
            "No padding byte(s) were removed."
        )

        return f"""
        <div style="font-family:Consolas; font-size:12px;">
        <u><b>Unpadding ({unpad_mode})</b></u><br>
        After decryption, the byte(s) may still contain padding byte(s) at the end.<br>
        Unpadding removes exactly those byte(s) to recover the original message.<br><br>

        <u><b>Color Key</b></u><br>
        <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = byte(s) that stay<br>
        <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = byte(s) removed as padding<br>
        <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

        <u><b>Byte(s) before unpadding</b></u>
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{before_dump}</pre>

        <u><b>Byte(s) after unpadding</b></u>
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{after_dump}</pre>

        <u><b>Removed padding byte(s)</b></u>
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{removed_dump}</pre>

        <u><b>Important: Why could errors happen?</b></u><br>
        Wrong key, wrong IV (CBC), wrong unpadding mode, or modified ciphertext.
        </div>
        """

    def _render_data_encrypt_html(self, mode: str, res) -> str:
        ct_blocks = self._html_or_sys_none(res.output_hex, "Ciphertext is empty.")
        key_blocks = self._html_or_sys_none(res.used_key_hex_blocks or "", "Key is empty.")
        iv_blocks  = self._html_or_sys_none(res.used_iv_hex_blocks or "", "IV/Counter is empty.")

        pad_mode = res.padding_mode

        data_tokens: list[str] = res.input_tokens or []
        padded_tokens: list[str] = res.padded_tokens or data_tokens
        pad_start: int = int(res.pad_start_index or len(data_tokens))

        input_dump = self._tokens_or_sys_none(
            data_tokens,
            lambda _i: BLUE,
            "Plaintext is empty (0 byte(s))."
        )

        no_padding = (mode == "CTR") or (pad_mode == "NONE")

        def color_padded(idx: int) -> str | None:
            if not no_padding and mode in ("ECB", "CBC") and idx >= pad_start:
                return DANGER_HOVER
            return BLUE

        padded_dump = self._tokens_or_sys_none(
            padded_tokens,
            color_padded,
            "Plaintext is empty (0 byte(s))."
        )

        if mode == "CTR":
            padded_note = "<div style='color:#6b7280; margin:4px 0 10px 0;'>CTR uses <b>no padding</b>. Shown byte(s) are exactly the input byte(s).</div>"
        elif pad_mode == "NONE":
            padded_note = "<div style='color:#6b7280; margin:4px 0 10px 0;'>Padding mode <b>NONE</b>: <b>no padding was added</b>. Padded byte(s) are identical to input.</div>"
        else:
            padded_note = ""

        iv_line = ""
        if mode in ("CBC", "CTR"):
            iv_line = f"""
            <u><b>IV / Counter (HEX)</b></u><br>
            {iv_blocks}<br><br>
            """

        return f"""
        <div style="font-family:Consolas; font-size:12px;">
        <u><b>Encryption output</b></u><br><br>

        <u><b>Mode</b></u><br>{mode}<br><br>

        <u><b>Ciphertext (HEX, 16-byte block(s))</b></u><br>{ct_blocks}<br><br>

        <u><b>Key (HEX)</b></u><br>{key_blocks}<br><br>

        {iv_line}

        <u><b>Color Key</b></u><br>
        <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = real data byte(s)<br>
        <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = padding byte(s) (ECB/CBC)<br>
        <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

        <u><b>Plaintext byte(s) (input)</b></u>
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{input_dump}</pre>

        <u><b>Padded plaintext byte(s)</b></u>
        {padded_note}
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{padded_dump}</pre>
        </div>
        """

    def _render_data_decrypt_html(self, mode: str, res) -> str:
        ct_blocks = self._html_or_sys_none(res.ciphertext_used_hex_blocks or "", "Ciphertext used is empty.")
        key_blocks = self._html_or_sys_none(res.used_key_hex_blocks or "", "Key is empty.")
        iv_blocks  = self._html_or_sys_none(res.used_iv_hex_blocks or "", "IV/Counter is empty.")

        unpad_mode = res.unpadding_mode
        text = self._html_or_sys_none(
            self._escape_html(res.output_text),
            "No UTF-8 text to show (empty or not decodable)."
        )

        raw_tokens: list[str] = res.decrypted_raw_tokens or []
        pad_len = int(res.removed_pad_len or 0)
        pad_start = int(res.removed_pad_start_index or max(0, len(raw_tokens) - pad_len))

        no_unpadding = (mode == "CTR") or (unpad_mode == "NONE")

        def color_before(idx: int) -> str | None:
            if not no_unpadding and mode in ("ECB", "CBC") and pad_len > 0 and idx >= pad_start:
                return DANGER_HOVER
            return BLUE

        raw_dump = self._tokens_or_sys_none(
            raw_tokens,
            color_before,
            "No decrypted byte(s) to show."
        )

        out_tokens: list[str] = res.output_tokens or []
        out_dump = self._tokens_or_sys_none(
            out_tokens,
            lambda _i: BLUE,
            "Plaintext is empty (0 byte(s))."
        )

        if mode == "CTR":
            unpad_note = "<div style='color:#6b7280; margin:4px 0 10px 0;'>CTR uses <b>no unpadding</b>. Output byte(s) are the direct CTR decryption result.</div>"
        elif unpad_mode == "NONE":
            unpad_note = "<div style='color:#6b7280; margin:4px 0 10px 0;'>Unpadding mode <b>NONE</b>: <b>no byte(s) were removed</b>. Output byte(s) stay the same as raw decrypted byte(s).</div>"
        else:
            unpad_note = ""

        iv_line = ""
        if mode in ("CBC", "CTR"):
            iv_line = f"""
            <u><b>IV / Counter (HEX)</b></u><br>
            {iv_blocks}<br><br>
            """

        return f"""
        <div style="font-family:Consolas; font-size:12px;">
        <u><b>Decryption output</b></u><br><br>

        <u><b>Mode</b></u><br>{mode}<br><br>

        <u><b>Ciphertext used</b></u><br>{ct_blocks}<br><br>

        <u><b>Key (HEX)</b></u><br>{key_blocks}<br><br>

        {iv_line}

        <u><b>Color Key</b></u><br>
        <b><span style="color:{BLUE}; font-weight:700;">Blue</span></b> = real data byte(s)<br>
        <b><span style="color:{DANGER_HOVER}; font-weight:700;">Red</span></b> = padding byte(s) (ECB/CBC)<br>
        <b><span style="color:{SYSTEM_GREEN}; font-weight:700;">Green</span></b> = system notice(s) (for example empty byte(s))<br><br>

        <u><b>Decrypted byte(s) before unpadding</b></u>
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{raw_dump}</pre>

        <u><b>Plaintext byte(s) after unpadding</b></u>
        {unpad_note}
        <pre style="background:#ffffff; padding:8px; border:1px solid #c7d7f2; border-radius:8px; white-space:pre-wrap;">{out_dump}</pre>

        <u><b>Plaintext (UTF-8 if possible)</b></u><br>{text}<br><br>
        </div>
        """

    def _on_encrypt(self) -> None:
        # clear on every attempt (no stale results)
        self._encrypt_dirty = True
        if self._is_encrypt_view():
            self._clear_right_panel()

        try:
            if not self._ensure_key_or_confirm_autogen_encrypt():
                return
            if not self._ensure_iv_or_confirm_autogen_encrypt():
                return

            mode = self._current_mode()
            fmt = self._current_input_format()
            padding_mode = self._current_padding_mode()

            plaintext = self.plaintext_edit.toPlainText()
            key_hex = self.key_edit.text()
            iv_hex = self.iv_edit.text() if self.iv_edit.isEnabled() else None

            res = self.vm.encrypt(
                mode=mode,
                plaintext=plaintext,
                input_format=fmt,
                key_hex=key_hex,
                iv_hex=iv_hex,
                padding_mode=padding_mode,
            )
            if not res.ok:
                self._show_error("Encryption failed.", res.error)
                return

            self._encrypt_dirty = False
            self._last_encrypt_res = res

            # update fields without triggering dirty logic
            with QSignalBlocker(self.ciphertext_edit):
                self.ciphertext_edit.setPlainText(res.output_hex)

            if res.used_iv_hex and self.iv_edit.isEnabled():
                with QSignalBlocker(self.iv_edit):
                    self.iv_edit.setText(res.used_iv_hex)

            if mode in ("ECB", "CBC"):
                self._set_unpadding_buttons(res.padding_mode or "PKCS7")

            pad_html = self._render_padding_encrypt_html(mode, res)
            data_html = self._render_data_encrypt_html(mode, res)

            self._encrypt_pad_html = pad_html
            self._encrypt_data_html = data_html

            self.padding_view.setHtml(pad_html)
            self.data_view.setHtml(data_html)

            # success details (Encrypt)
            lines: list[str] = []
            lines.append(f"- Mode: {mode}")
            lines.append(f"- Ciphertext (HEX): {res.output_hex or ''}")
            lines.append(f"- Key (HEX): {res.used_key_hex or ''}")

            if mode in ("CBC", "CTR"):
                lines.append(f"- IV/Counter (HEX): {res.used_iv_hex or ''}")

            if mode in ("ECB", "CBC"):
                lines.append(f"- Unpadding mode: {res.padding_mode or 'PKCS7'}")

            details_text = "\n".join(lines)
            self._show_success("Encryption completed.", details_text)

        except Exception as e:
            self._show_error("Encryption failed.", str(e))

    def _on_decrypt(self) -> None:
        # clear on every attempt (no stale results)
        self._decrypt_dirty = True
        if not self._is_encrypt_view():
            self._clear_right_panel()

        try:
            mode = self._current_mode()
            unpadding_mode = self._current_unpadding_mode()

            ct_text = self.ciphertext_edit.toPlainText()
            key_hex = self.key_edit.text()
            iv_hex = self.iv_edit.text() if self.iv_edit.isEnabled() else None

            res = self.vm.decrypt(
                mode=mode,
                ciphertext_hex=ct_text,
                key_hex=key_hex,
                iv_hex=iv_hex,
                unpadding_mode=unpadding_mode,
            )
            if not res.ok:
                self._show_error("Decryption failed.", res.error)
                return

            self._decrypt_dirty = False
            self._last_decrypt_res = res

            if mode in ("ECB", "CBC"):
                self._set_padding_buttons(res.unpadding_mode or "PKCS7")

            pad_html = self._render_padding_decrypt_html(mode, res)
            data_html = self._render_data_decrypt_html(mode, res)

            self._decrypt_pad_html = pad_html
            self._decrypt_data_html = data_html

            self.padding_view.setHtml(pad_html)
            self.data_view.setHtml(data_html)

            # success details (Decrypt)
            lines: list[str] = []
            lines.append(f"- Mode: {mode}")
            lines.append(f"- Plaintext (HEX): {res.output_hex or ''}")
            lines.append(f"- Plaintext (UTF-8): {(res.output_text or '').strip()}")
            lines.append(f"- Key (HEX): {res.used_key_hex or ''}")

            if mode in ("CBC", "CTR"):
                lines.append(f"- IV/Counter (HEX): {res.used_iv_hex or ''}")

            if mode in ("ECB", "CBC"):
                lines.append(f"- Padding mode: {res.unpadding_mode or 'PKCS7'}")

            details_text = "\n".join(lines)
            self._show_success("Decryption completed.", details_text)

        except Exception as e:
            self._show_error("Decryption failed.", str(e))

    def _on_clear(self) -> None:
        with QSignalBlocker(self.plaintext_edit):
            self.plaintext_edit.clear()
        with QSignalBlocker(self.ciphertext_edit):
            self.ciphertext_edit.clear()
        with QSignalBlocker(self.key_edit):
            self.key_edit.clear()
        with QSignalBlocker(self.iv_edit):
            self.iv_edit.clear()

        self._clear_right_panel()

        self._encrypt_dirty = True
        self._decrypt_dirty = True

        self._encrypt_pad_html = ""
        self._encrypt_data_html = ""
        self._decrypt_pad_html = ""
        self._decrypt_data_html = ""
