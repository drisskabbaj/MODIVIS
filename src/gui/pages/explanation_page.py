from __future__ import annotations  # needed so type hints can reference classes that are defined later (avoids forward-reference issues)

from dataclasses import dataclass  # needed to define small typed data holders for UI state
from typing import Callable  # needed for callback type hints

from PySide6.QtCore import Qt, QTimer, QRectF, Property, QEasingCurve, QPointF, QSignalBlocker, QSize  # needed for alignment constants, scheduling UI updates, geometry for painting, Qt properties, animations, points, safe signal blocking, and size values
from PySide6.QtGui import QFont, QPainter, QPen, QColor, QBrush  # needed for fonts and custom drawing (animated diagrams, highlights and backgrounds)

from src.domain.crypto_types import Mode  # needed for type-safe mode of operation values
from src.domain.padding_types import PaddingMode  # needed for type-safe padding scheme values

from PySide6.QtWidgets import (  # needed to build the explanation UI (layouts, toggles, tables, scrolling and sizing)
    QWidget,              # needed as the base widget for the page
    QVBoxLayout,          # needed for vertical stacking layouts
    QHBoxLayout,          # needed for horizontal row layouts
    QBoxLayout,           # needed when a helper accepts both QVBoxLayout and QHBoxLayout
    QLabel,               # needed for titles, captions, and helper text
    QGroupBox,            # needed for titled containers (visual grouping for sections)
    QToolButton,          # needed for toggle-style buttons (mode/padding selectors)
    QButtonGroup,         # needed to enforce exclusive selection for toggle groups
    QPushButton,          # needed for actions (next, back, reset, play...)
    QStackedWidget,       # needed to switch between multiple pages/steps inside the explanation
    QSlider,              # needed for interactive controls (for example speed or progress)
    QLineEdit,            # needed for small user inputs (for example step count or search/filter text)
    QTableWidget,         # needed for pros/cons and comparison tables
    QTableWidgetItem,     # needed to populate table cells with text
    QHeaderView,          # needed to configure table headers (stretch, resize modes)
    QAbstractScrollArea,  # needed to tune scrolling behavior for tables and scrollable widgets
    QScrollArea,          # needed to make long content scrollable inside the page
    QFrame,               # needed for separators and lightweight containers
    QSizePolicy,          # needed to control widget grow/shrink behavior in layouts
)

# =========================
# Color palette
# =========================
BLUE = "#2f80ed"         # used for the primary theme (selected toggles + primary actions)
BLUE_HOVER = "#256bd6"   # used when hovering primary buttons
BLUE_PRESSED = "#1f5bb8" # used when pressing primary buttons

DANGER_HOVER = "#be123c"    # used for hover states and as a highlight color in explanations
WARNING = "#f59e0b"         # used for warning actions (eg. reset to defaults)
WARNING_HOVER = "#d97706"   # used when hovering warning buttons
WARNING_PRESSED = "#b45309" # used when pressing warning buttons

DANGER = "#D2042D"         # used for destructive actions (eg. clear or delete btn.)
DANGER_PRESSED = "#9f1239" # used when pressing destructive buttons

PANEL_BG = "#eef5ff"     # used as the background color of group boxes (light panel)
PANEL_BORDER = "#c7d7f2" # used as the border color of group boxes
TITLE_BG = "#ffffff"     # used as the background color of group box titles
TEXT_HINT = "#334155"    # used for helper text and small hints
TEXT_DARK = "#0f172a"    # used for strong titles and important labels

# =========================
# Domain constants
# =========================
MODES: tuple[Mode, ...] = ("ECB", "CBC", "CTR")  # used to render the mode selector and validate navigation logic
PADDING_MODES: tuple[PaddingMode, ...] = ("PKCS7", "X923", "ISO/IEC 7816-4")  # used for the padding selector and demo pages

MODE_PROS_TABLE_HEIGHT = 200       # used as a soft height guideline when shrinking the mode pros/cons table
PADDING_PROS_TABLE_HEIGHT = 200    # used as a soft height guideline when shrinking the padding pros/cons table
PADDING_WORKFLOW_MAX_HEIGHT = 360  # used to cap the workflow panel height so it stays readable without taking over the page

# =========================
# Disabled look helper
# =========================
# This striped gradient is used in QSS for disabled widgets so disabled is visually obvious.

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

# =========================
# QSS: Toggle buttons
# =========================
# Used for mode and padding selectors (exclusive toggle rows).

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

# =========================
# QSS: Primary buttons
# =========================
# Used for main actions (eg. Next / Back / Play).

PRIMARY_BTN_QSS = f"""
QPushButton {{
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid {BLUE};
    background: {BLUE};
    color: white;
    font-weight: 800;
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

# =========================
# QSS: Warning buttons
# =========================
# Used for caution actions (eg. Reset or Show details).

WARNING_BTN_QSS = f"""
QPushButton {{
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid {WARNING};
    background: {WARNING};
    color: #111827;
    font-weight: 800;
    min-width: 120px;
}}
QPushButton:hover {{
    background: {WARNING_HOVER};
    border-color: {WARNING_HOVER};
}}
QPushButton:pressed {{
    background: {WARNING_PRESSED};
    border-color: {WARNING_PRESSED};
}}
QPushButton:disabled {{
    color: #6b7280;
    border: 1px solid #c6c6c6;
    background: {DISABLED_STRIPES_BG};
}}
"""

# =========================
# QSS: Danger buttons
# =========================
# Used for destructive actions (for example Clear or Delete).

DANGER_BTN_QSS = f"""
QPushButton {{
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid {DANGER};
    background: {DANGER};
    color: white;
    font-weight: 800;
    min-width: 120px;
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


def _mono_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setFont(QFont("Consolas", 10))
    label.setStyleSheet(f"color:{TEXT_DARK};")
    return label


def _hex(n: int) -> str:
    return "0123456789ABCDEF"[n & 0xF]


def _xor(a: int, b: int) -> int:
    return (a ^ b) & 0xF


def _table_item(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
    item.setTextAlignment(Qt.AlignCenter)
    return item


def _shrink_table(
    table: QTableWidget,
    max_height: int | None = None,
    min_height: int | None = None,
) -> None:
    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    height = table.horizontalHeader().height()
    for row in range(table.rowCount()):
        height += table.rowHeight(row)
    height += table.frameWidth() * 2
    if max_height is not None:
        height = min(height, max_height)
    if min_height is not None:
        height = max(height, min_height)
    table.setFixedHeight(height)


class DiagramWidget(QWidget):
    def __init__(self, mode: Mode) -> None:
        super().__init__()
        self._mode = mode
        self._encrypt = True
        self._active_step = 0
        self._cbc_active_block = 0
        self._cbc_prev_step = None
        self._highlight_alpha = 0.0
        self._animation = None
        if mode == MODES[0]:
            min_height = 100
            min_width = 560
        elif mode == MODES[1]:
            min_height = 240
            min_width = 700
        else:
            min_height = 200
            min_width = 1500
        self.setMinimumHeight(min_height)
        self.setMinimumWidth(min_width)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setAutoFillBackground(False)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def set_encrypt(self, encrypt: bool) -> None:
        self._encrypt = encrypt
        self.update()

    def set_active_step(self, step: int) -> None:
        if self._mode == MODES[1] and self._cbc_prev_step is not None:
            if self._cbc_prev_step == 3 and step == 0:
                self._cbc_active_block = (self._cbc_active_block + 1) % 3
        self._cbc_prev_step = step
        self._active_step = step
        self._start_pulse()

    def _start_pulse(self) -> None:
        from PySide6.QtCore import QPropertyAnimation

        if self._animation:
            self._animation.stop()
        self._highlight_alpha = 0.2
        self._animation = QPropertyAnimation(self, b"highlightAlpha")
        self._animation.setStartValue(0.2)
        self._animation.setEndValue(1.0)
        self._animation.setDuration(420)
        self._animation.setEasingCurve(QEasingCurve.OutQuad)
        self._animation.start()

    def _draw_block(self, painter: QPainter, rect: QRectF, text: str, active: bool = False) -> None:
        if active:
            painter.setPen(QPen(QColor(BLUE), 1))
            painter.setBrush(QBrush(QColor(BLUE)))
            painter.drawRoundedRect(rect, 6, 6)
            painter.setPen(QPen(QColor("white"), 1))
            painter.drawText(rect, Qt.AlignCenter, text)
            return
        painter.setPen(QPen(QColor(PANEL_BORDER), 1))
        painter.setBrush(QBrush(QColor(TITLE_BG)))
        painter.drawRoundedRect(rect, 6, 6)
        painter.setPen(QPen(QColor(TEXT_DARK), 1))
        painter.drawText(rect, Qt.AlignCenter, text)

    def _draw_arrow(
        self,
        painter: QPainter,
        start: QPointF,
        end: QPointF,
        head_size: float = 10.0,
        active: bool = False,
    ) -> None:
        color = QColor(BLUE) if active else QColor(TEXT_HINT)
        width = 3 if active else 2
        painter.setPen(QPen(color, width))
        painter.drawLine(start, end)
        angle = 0.45
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = max((dx * dx + dy * dy) ** 0.5, 1.0)
        ux, uy = dx / length, dy / length
        left = QPointF(
            end.x() - head_size * (ux * 0.7 + uy * angle),
            end.y() - head_size * (uy * 0.7 - ux * angle),
        )
        right = QPointF(
            end.x() - head_size * (ux * 0.7 - uy * angle),
            end.y() - head_size * (uy * 0.7 + ux * angle),
        )
        painter.drawLine(end, left)
        painter.drawLine(end, right)

    def _draw_arrow_trimmed(
        self,
        painter: QPainter,
        start: QPointF,
        end: QPointF,
        trim: float,
        head_size: float = 10.0,
    ) -> None:
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = max((dx * dx + dy * dy) ** 0.5, 1.0)
        trim = max(0.0, min(trim, length * 0.45))
        ux, uy = dx / length, dy / length
        trimmed_start = QPointF(start.x() + ux * trim, start.y() + uy * trim)
        trimmed_end = QPointF(end.x() - ux * trim, end.y() - uy * trim)
        self._draw_arrow(painter, trimmed_start, trimmed_end, head_size=head_size)

    def _draw_arrow_trimmed(
        self,
        painter: QPainter,
        start: QPointF,
        end: QPointF,
        trim: float,
        head_size: float = 10.0,
    ) -> None:
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = max((dx * dx + dy * dy) ** 0.5, 1.0)
        trim = max(0.0, min(trim, length * 0.45))
        ux, uy = dx / length, dy / length
        trimmed_start = QPointF(start.x() + ux * trim, start.y() + uy * trim)
        trimmed_end = QPointF(end.x() - ux * trim, end.y() - uy * trim)
        self._draw_arrow(painter, trimmed_start, trimmed_end, head_size=head_size)

    def _draw_xor(self, painter: QPainter, center: QPointF, radius: float, active: bool = False) -> None:
        if active:
            painter.setPen(QPen(QColor(BLUE), 2))
            painter.setBrush(QBrush(QColor(BLUE)))
            painter.drawEllipse(center, radius, radius)
            painter.setPen(QPen(QColor("white"), 1))
        else:
            painter.setPen(QPen(QColor(BLUE), 2))
            painter.setBrush(QBrush(QColor(TITLE_BG)))
            painter.drawEllipse(center, radius, radius)
            painter.setPen(QPen(QColor(TEXT_DARK), 1))
        painter.drawText(
            QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2),
            Qt.AlignCenter,
            "XOR",
        )

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width = float(self.width())
        height = float(self.height())
        center_y = height * 0.32

        margin = 24.0
        block_w = 120.0
        block_h = 38.0
        block_y = center_y - block_h / 2

        input_label = "Plaintext" if self._encrypt else "Ciphertext"
        output_label = "Ciphertext" if self._encrypt else "Plaintext"
        cipher_label = "Eₖ" if self._mode == MODES[2] else ("Eₖ" if self._encrypt else "Dₖ")

        if self._mode == MODES[0]:
            input_rect = QRectF(margin, block_y, block_w, block_h)
            cipher_rect = QRectF(width / 2 - block_w / 2, block_y, block_w, block_h)
            output_rect = QRectF(width - margin - block_w, block_y, block_w, block_h)

            if self._encrypt:
                active_input = self._active_step in (0, 1)
                active_cipher = self._active_step == 2
                active_output = self._active_step == 3
                active_in_arrow = self._active_step in (1, 2)
                active_out_arrow = self._active_step == 3
            else:
                active_input = self._active_step in (0, 1)
                active_cipher = self._active_step == 1
                active_output = self._active_step in (2, 3)
                active_in_arrow = self._active_step == 1
                active_out_arrow = self._active_step == 2

            self._draw_block(painter, input_rect, input_label, active_input)
            self._draw_block(painter, cipher_rect, cipher_label, active_cipher)
            self._draw_block(painter, output_rect, output_label, active_output)

            self._draw_arrow(
                painter,
                QPointF(input_rect.right(), center_y),
                QPointF(cipher_rect.left(), center_y),
                active=active_in_arrow,
            )
            self._draw_arrow(
                painter,
                QPointF(cipher_rect.right(), center_y),
                QPointF(output_rect.left(), center_y),
                active=active_out_arrow,
            )
            return

        if self._mode == MODES[1]:
            columns = 3
            col_w = (width - margin * 2) / columns
            block_w = min(120.0, col_w * 0.6)
            block_h = 30.0
            top_y = 12.0
            xor_y = height * 0.42
            cipher_y = height * 0.58
            out_y = height * 0.80
            xor_radius = 15.0

            if self._encrypt:
                rule1 = self._active_step == 0
                rule2 = self._active_step == 1
                rule3 = self._active_step == 2
                rule4 = self._active_step == 3
                active_block = self._cbc_active_block
            else:
                rule1 = self._active_step == 0
                rule2 = self._active_step == 1
                rule3 = self._active_step == 2
                rule4 = self._active_step == 3

            for idx in range(columns):
                x_center = margin + col_w * (idx + 0.5)
                input_rect = QRectF(x_center - block_w / 2, top_y, block_w, block_h)
                xor_center = QPointF(x_center, xor_y)
                cipher_rect = QRectF(x_center - block_w / 2, cipher_y, block_w, block_h)
                output_rect = QRectF(x_center - block_w / 2, out_y, block_w, block_h)

                if self._encrypt:
                    in_label = f"{input_label}_{idx + 1}"
                    out_label = f"{output_label}_{idx + 1}"
                else:
                    in_label = f"Plaintext_{idx + 1}"
                    out_label = f"Ciphertext_{idx + 1}"
                if self._encrypt:
                    is_active_block = idx == active_block
                    active_input_local = (rule1 or rule2) and is_active_block
                    active_xor_local = rule2 and is_active_block
                    active_cipher_local = rule3 and is_active_block
                    active_output_local = (rule4 and is_active_block) or (rule2 and idx == active_block - 1)
                    active_iv_local = rule2 and active_block == 0 and idx == 0
                else:
                    active_input_local = rule3 or rule4
                    active_xor_local = rule2
                    active_cipher_local = rule1
                    active_output_local = rule1 or (rule2 and idx < columns - 1)
                    active_iv_local = rule2 and idx == 0

                self._draw_block(painter, input_rect, in_label, active_input_local)
                self._draw_xor(painter, xor_center, xor_radius, active_xor_local)
                self._draw_block(painter, cipher_rect, cipher_label, active_cipher_local)
                self._draw_block(painter, output_rect, out_label, active_output_local)

                if idx == 0:
                    iv_rect = QRectF(x_center - block_w / 2 - 70, xor_y - 12, 60, 24)
                    self._draw_block(painter, iv_rect, "IV", active_iv_local)
                    self._draw_arrow(
                        painter,
                        QPointF(iv_rect.right(), xor_center.y()),
                        QPointF(xor_center.x() - xor_radius, xor_center.y()),
                        active=(rule2 and active_block == 0) if self._encrypt else active_iv_local,
                    )

                if self._encrypt:
                    self._draw_arrow(
                        painter,
                        QPointF(input_rect.center().x(), input_rect.bottom()),
                        QPointF(xor_center.x(), xor_center.y() - xor_radius),
                        active=rule2 and is_active_block,
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(xor_center.x(), xor_center.y() + xor_radius),
                        QPointF(cipher_rect.center().x(), cipher_rect.top()),
                        active=rule3 and is_active_block,
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                        QPointF(output_rect.center().x(), output_rect.top()),
                    )
                else:
                    active_cipher_arrow = rule1
                    active_cipher_to_xor = rule2
                    active_xor_to_input = rule3
                    self._draw_arrow(
                        painter,
                        QPointF(output_rect.center().x(), output_rect.top()),
                        QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                        active=active_cipher_arrow,
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(cipher_rect.center().x(), cipher_rect.top()),
                        QPointF(xor_center.x(), xor_center.y() + xor_radius),
                        active=active_cipher_to_xor,
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(xor_center.x(), xor_center.y() - xor_radius),
                        QPointF(input_rect.center().x(), input_rect.bottom()),
                        active=active_xor_to_input,
                    )

                if idx > 0:
                    prev_out_center = margin + col_w * (idx - 0.5)
                    if self._encrypt:
                        chain_into_xor = rule2 and idx == active_block and active_block > 0
                        chain_to_next = rule4 and idx == active_block + 1
                        self._draw_arrow(
                            painter,
                            QPointF(prev_out_center + block_w / 2, out_y + block_h / 2),
                            QPointF(x_center - xor_radius, xor_center.y()),
                            active=chain_into_xor or chain_to_next,
                        )
                    else:
                        self._draw_arrow(
                            painter,
                            QPointF(prev_out_center + block_w / 2, out_y + block_h / 2),
                            QPointF(x_center - xor_radius, xor_center.y()),
                            active=rule2,
                        )
            return

        if self._mode == MODES[2]:
            columns = 3
            spacing = max(50.0, width * 0.04)
            col_w = (width - margin * 2 - spacing * (columns - 1)) / columns
            block_w = min(130.0, col_w * 0.55)
            block_h = 30.0
            top_y = 12.0
            cipher_y = height * 0.34
            xor_y = height * 0.62
            out_y = height * 0.80
            xor_radius = 15.0
            input_offset = min(150.0, col_w * 0.4)

            active_counter = self._active_step == 0
            active_cipher = self._active_step == 1
            active_xor = self._active_step == 2
            active_input = self._active_step == 2
            active_output = self._active_step == 2

            for idx in range(columns):
                x_center = margin + col_w * (idx + 0.5) + spacing * idx
                input_w = 80.0
                max_offset = max(40.0, x_center - margin - input_w)
                local_offset = min(input_offset, max_offset)
                counter_rect = QRectF(x_center - block_w / 2, top_y, block_w, block_h)
                cipher_rect = QRectF(x_center - block_w / 2, cipher_y, block_w, block_h)
                xor_center = QPointF(x_center, xor_y)
                input_rect = QRectF(x_center - local_offset - input_w, xor_y - block_h / 2, input_w, block_h)
                output_rect = QRectF(x_center - block_w / 2, out_y, block_w, block_h)

                in_label = f"{input_label}_{idx + 1}"
                out_label = f"{output_label}_{idx + 1}"
                ctr_label = f"Nonce||Counter_{idx + 1}"

                self._draw_block(painter, input_rect, in_label, active_input)
                self._draw_xor(painter, xor_center, xor_radius, active_xor)
                self._draw_block(painter, cipher_rect, cipher_label, active_cipher)
                self._draw_block(painter, counter_rect, ctr_label, active_counter)
                self._draw_block(painter, output_rect, out_label, active_output)

                self._draw_arrow(
                    painter,
                    QPointF(input_rect.right(), xor_center.y()),
                    QPointF(xor_center.x() - xor_radius - 2, xor_center.y()),
                    active=active_input,
                )
                self._draw_arrow(
                    painter,
                    QPointF(xor_center.x(), xor_center.y() + xor_radius),
                    QPointF(output_rect.center().x(), output_rect.top()),
                    active=active_output,
                )
                self._draw_arrow(
                    painter,
                    QPointF(counter_rect.center().x(), counter_rect.bottom()),
                    QPointF(cipher_rect.center().x(), cipher_rect.top()),
                    active=active_cipher,
                )
                self._draw_arrow(
                    painter,
                    QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                    QPointF(xor_center.x(), xor_center.y() - xor_radius),
                    active=active_cipher,
                )
            return

    def get_highlight_alpha(self) -> float:
        return self._highlight_alpha

    def set_highlight_alpha(self, value: float) -> None:
        self._highlight_alpha = value
        self.update()

    highlightAlpha = Property(float, get_highlight_alpha, set_highlight_alpha)


@dataclass
class ExampleStep:
    input_label: str
    output_label: str
    cipher_label: str
    iv_label: str | None = None
    counter_label: str | None = None


@dataclass
class ExamplePayload:
    steps: list[ExampleStep]
    given_line: str
    mapping_questions: list[str]
    final_line: str


class ExampleDiagramWidget(QWidget):
    def __init__(self, mode: Mode) -> None:
        super().__init__()
        self._mode = mode
        self._encrypt = True
        self._steps: list[ExampleStep] = []
        self._step_index = 0
        if mode == MODES[0]:
            min_height = 60
            min_width = 560
        elif mode == MODES[1]:
            min_height = 180
            min_width = 700
        else:
            min_height = 200
            min_width = 1500
        self.setMinimumHeight(min_height)
        self.setMinimumWidth(min_width)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setAutoFillBackground(False)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def set_encrypt(self, encrypt: bool) -> None:
        self._encrypt = encrypt
        self.update()

    def set_steps(self, steps: list[ExampleStep]) -> None:
        self._steps = steps
        self._step_index = 0
        self.update()

    def set_step_index(self, index: int) -> None:
        if not self._steps:
            self._step_index = 0
        else:
            self._step_index = max(0, min(index, len(self._steps) - 1))
        self.update()

    def _current_step(self) -> ExampleStep:
        if not self._steps:
            return ExampleStep("P", "C", "Eₖ")
        return self._steps[self._step_index]

    def _draw_block(self, painter: QPainter, rect: QRectF, text: str) -> None:
        painter.setPen(QPen(QColor(PANEL_BORDER), 1))
        painter.setBrush(QBrush(QColor(TITLE_BG)))
        painter.drawRoundedRect(rect, 6, 6)
        painter.setPen(QPen(QColor(TEXT_DARK), 1))
        painter.drawText(rect, Qt.AlignCenter, text)

    def _draw_arrow(
        self, painter: QPainter, start: QPointF, end: QPointF, head_size: float = 10.0
    ) -> None:
        painter.setPen(QPen(QColor(TEXT_HINT), 2))
        painter.drawLine(start, end)
        angle = 0.45
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = max((dx * dx + dy * dy) ** 0.5, 1.0)
        ux, uy = dx / length, dy / length
        left = QPointF(
            end.x() - head_size * (ux * 0.7 + uy * angle),
            end.y() - head_size * (uy * 0.7 - ux * angle),
        )
        right = QPointF(
            end.x() - head_size * (ux * 0.7 - uy * angle),
            end.y() - head_size * (uy * 0.7 + ux * angle),
        )
        painter.drawLine(end, left)
        painter.drawLine(end, right)

    def _draw_xor(self, painter: QPainter, center: QPointF, radius: float) -> None:
        painter.setPen(QPen(QColor(BLUE), 2))
        painter.setBrush(QBrush(QColor(TITLE_BG)))
        painter.drawEllipse(center, radius, radius)
        painter.setPen(QPen(QColor(TEXT_DARK), 1))
        painter.drawText(
            QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2),
            Qt.AlignCenter,
            "XOR",
        )

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width = float(self.width())
        height = float(self.height())
        center_y = height * 0.30

        margin = 24.0
        block_w = 140.0
        block_h = 38.0
        block_y = center_y - block_h / 2

        step = self._current_step()

        if self._mode == MODES[0]:
            input_rect = QRectF(margin, block_y, block_w, block_h)
            cipher_rect = QRectF(width / 2 - block_w / 2, block_y, block_w, block_h)
            output_rect = QRectF(width - margin - block_w, block_y, block_w, block_h)

            self._draw_block(painter, input_rect, step.input_label)
            self._draw_block(painter, cipher_rect, step.cipher_label)
            self._draw_block(painter, output_rect, step.output_label)
            self._draw_arrow(
                painter,
                QPointF(input_rect.right(), center_y),
                QPointF(cipher_rect.left(), center_y),
            )
            self._draw_arrow(
                painter,
                QPointF(cipher_rect.right(), center_y),
                QPointF(output_rect.left(), center_y),
            )
            return

        if self._mode == MODES[1]:
            columns = max(1, len(self._steps))
            col_w = (width - margin * 2) / columns
            block_w = min(120.0, col_w * 0.6)
            block_h = 30.0
            top_y = 12.0
            xor_y = height * 0.42
            cipher_y = height * 0.58
            out_y = height * 0.80
            xor_radius = 15.0

            for idx, step_item in enumerate(self._steps):
                x_center = margin + col_w * (idx + 0.5)
                input_rect = QRectF(x_center - block_w / 2, top_y, block_w, block_h)
                xor_center = QPointF(x_center, xor_y)
                cipher_rect = QRectF(x_center - block_w / 2, cipher_y, block_w, block_h)
                output_rect = QRectF(x_center - block_w / 2, out_y, block_w, block_h)

                if self._encrypt:
                    top_label = step_item.input_label
                    bottom_label = step_item.output_label
                else:
                    top_label = step_item.output_label
                    bottom_label = step_item.input_label
                self._draw_block(painter, input_rect, top_label)
                self._draw_xor(painter, xor_center, xor_radius)
                self._draw_block(painter, cipher_rect, step_item.cipher_label)
                self._draw_block(painter, output_rect, bottom_label)

                if idx == 0:
                    iv_rect = QRectF(x_center - block_w / 2 - 70, xor_y - 12, 60, 24)
                    self._draw_block(painter, iv_rect, step_item.iv_label or "IV")
                    self._draw_arrow(
                        painter,
                        QPointF(iv_rect.right(), xor_center.y()),
                        QPointF(xor_center.x() - xor_radius, xor_center.y()),
                    )
                if self._encrypt:
                    self._draw_arrow(
                        painter,
                        QPointF(xor_center.x(), xor_center.y() - xor_radius),
                        QPointF(input_rect.center().x(), input_rect.bottom()),
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(xor_center.x(), xor_center.y() + xor_radius),
                        QPointF(cipher_rect.center().x(), cipher_rect.top()),
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                        QPointF(output_rect.center().x(), output_rect.top()),
                    )
                else:
                    self._draw_arrow(
                        painter,
                        QPointF(output_rect.center().x(), output_rect.top()),
                        QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(cipher_rect.center().x(), cipher_rect.top()),
                        QPointF(xor_center.x(), xor_center.y() + xor_radius),
                    )
                    self._draw_arrow(
                        painter,
                        QPointF(input_rect.center().x(), input_rect.bottom()),
                        QPointF(xor_center.x(), xor_center.y() - xor_radius),
                    )

                if idx > 0:
                    prev_out_center = margin + col_w * (idx - 0.5)
                    if self._encrypt:
                        self._draw_arrow(
                            painter,
                            QPointF(prev_out_center + block_w / 2, out_y + block_h / 2),
                            QPointF(x_center - xor_radius, xor_center.y()),
                        )
                    else:
                        self._draw_arrow(
                            painter,
                            QPointF(prev_out_center + block_w / 2, out_y + block_h / 2),
                            QPointF(x_center - xor_radius, xor_center.y()),
                        )
            return

        if self._mode == MODES[2]:
            columns = max(1, len(self._steps))
            spacing = max(50.0, width * 0.04)
            col_w = (width - margin * 2 - spacing * (columns - 1)) / columns
            block_w = min(130.0, col_w * 0.55)
            block_h = 30.0
            top_y = 12.0
            cipher_y = height * 0.34
            xor_y = height * 0.62
            out_y = height * 0.80
            xor_radius = 15.0
            input_offset = min(150.0, col_w * 0.4)

            for idx, step_item in enumerate(self._steps):
                x_center = margin + col_w * (idx + 0.5) + spacing * idx
                input_w = 80.0
                max_offset = max(40.0, x_center - margin - input_w)
                local_offset = min(input_offset, max_offset)
                counter_rect = QRectF(x_center - block_w / 2, top_y, block_w, block_h)
                cipher_rect = QRectF(x_center - block_w / 2, cipher_y, block_w, block_h)
                xor_center = QPointF(x_center, xor_y)
                input_rect = QRectF(x_center - local_offset - input_w, xor_y - block_h / 2, input_w, block_h)
                output_rect = QRectF(x_center - block_w / 2, out_y, block_w, block_h)

                self._draw_block(painter, input_rect, step_item.input_label)
                self._draw_xor(painter, xor_center, xor_radius)
                self._draw_block(painter, cipher_rect, step_item.cipher_label)
                self._draw_block(painter, counter_rect, step_item.counter_label or "Nonce||Counter_")
                self._draw_block(painter, output_rect, step_item.output_label)

                self._draw_arrow(
                    painter,
                    QPointF(input_rect.right(), xor_center.y()),
                    QPointF(xor_center.x() - xor_radius - 2, xor_center.y()),
                )
                self._draw_arrow(
                    painter,
                    QPointF(xor_center.x(), xor_center.y() + xor_radius),
                    QPointF(output_rect.center().x(), output_rect.top()),
                )
                self._draw_arrow(
                    painter,
                    QPointF(counter_rect.center().x(), counter_rect.bottom()),
                    QPointF(cipher_rect.center().x(), cipher_rect.top()),
                )
                self._draw_arrow(
                    painter,
                    QPointF(cipher_rect.center().x(), cipher_rect.bottom()),
                    QPointF(xor_center.x(), xor_center.y() - xor_radius),
                )
            return


class ClickableLabel(QLabel):
    def __init__(self, text: str, index: int, handler) -> None:
        super().__init__(text)
        self._index = index
        self._handler = handler
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, event) -> None:
        if callable(self._handler):
            self._handler(self._index)
        super().mousePressEvent(event)


class ModeTab(QWidget):
    def __init__(
        self,
        mode: Mode,
        description: str,
        workflow_encrypt: list[str],
        workflow_decrypt: list[str],
        pros_cons: list[tuple[str, str]],
        example_builder: Callable[[bool], ExamplePayload],
    ) -> None:
        super().__init__()
        self._mode = mode
        self._workflow_encrypt = workflow_encrypt
        self._workflow_decrypt = workflow_decrypt
        self._example_builder = example_builder

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        desc = QLabel(description)
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{TEXT_HINT}; font-weight:700;")
        layout.addWidget(desc)

        self._workflow_box = QGroupBox("Workflow")
        self._workflow_layout = QVBoxLayout(self._workflow_box)
        self._workflow_layout.setSpacing(6)

        toggle_row = QHBoxLayout()
        toggle_row.addStretch(1)
        self._enc_btn = QToolButton()
        self._enc_btn.setText("Encrypt")
        self._enc_btn.setCheckable(True)
        self._dec_btn = QToolButton()
        self._dec_btn.setText("Decrypt")
        self._dec_btn.setCheckable(True)
        self._enc_btn.setStyleSheet(TOGGLE_QSS)
        self._dec_btn.setStyleSheet(TOGGLE_QSS)
        self._enc_btn.setChecked(True)
        self._enc_btn.setAutoExclusive(True)
        self._dec_btn.setAutoExclusive(True)
        toggle_row.addWidget(self._enc_btn)
        toggle_row.addWidget(self._dec_btn)
        toggle_row.addStretch(1)
        self._workflow_layout.addLayout(toggle_row)

        steps_row = QHBoxLayout()
        steps_row.setSpacing(12)
        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.setSpacing(6)
        steps_row.addWidget(self._steps_container, 1)

        pros_box = QGroupBox("Benefits / Drawbacks")
        pros_layout = QVBoxLayout(pros_box)
        pros_table = QTableWidget(len(pros_cons), 2)
        pros_table.setHorizontalHeaderLabels(["Benefits", "Drawbacks"])
        pros_table.verticalHeader().setVisible(False)
        pros_table.setEditTriggers(QTableWidget.NoEditTriggers)
        pros_table.setSelectionMode(QTableWidget.NoSelection)
        pros_table.setWordWrap(True)
        pros_table.setTextElideMode(Qt.ElideNone)
        pros_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        pros_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        pros_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        pros_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        pros_table.setStyleSheet(
            f"QTableWidget {{ background: transparent; gridline-color:{PANEL_BORDER}; }} "
            f"QTableWidget::item {{ background:{TITLE_BG}; }} "
            f"QHeaderView::section {{ background:{PANEL_BG}; border:1px solid {PANEL_BORDER}; font-weight:700; }}"
        )
        pros_table.horizontalHeader().setStretchLastSection(False)
        pros_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        pros_table.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        pros_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        for row, (pro, con) in enumerate(pros_cons):
            pros_table.setItem(row, 0, _table_item(pro))
            pros_table.setItem(row, 1, _table_item(con))
        pros_table.resizeRowsToContents()
        QTimer.singleShot(
            0,
            lambda t=pros_table: _shrink_table(
                t,
                max_height=MODE_PROS_TABLE_HEIGHT,
                min_height=MODE_PROS_TABLE_HEIGHT,
            ),
        )
        pros_layout.addWidget(pros_table)
        steps_row.addWidget(pros_box, 1)
        self._workflow_layout.addLayout(steps_row)

        self._diagram_box = QGroupBox("Diagram")
        diagram_layout = QVBoxLayout(self._diagram_box)
        diagram_layout.setContentsMargins(10, 14, 10, 10)
        diagram_layout.setSpacing(8)
        self._diagram_widget = DiagramWidget(mode)
        self._diagram_scroll = QScrollArea()
        self._diagram_scroll.setWidgetResizable(True)
        self._diagram_scroll.setFrameShape(QFrame.NoFrame)
        self._diagram_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._diagram_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._diagram_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._diagram_scroll.setMinimumHeight(self._diagram_widget.minimumHeight() + 6)
        self._diagram_scroll.setStyleSheet(
            "QScrollArea { background: transparent; } QScrollArea::viewport { background: transparent; }"
        )
        self._diagram_scroll.setAutoFillBackground(False)
        self._diagram_scroll.viewport().setAutoFillBackground(False)
        self._diagram_scroll.setWidget(self._diagram_widget)
        diagram_layout.addWidget(self._diagram_scroll, 1)
        diagram_layout.addSpacing(2)

        control_row = QHBoxLayout()
        control_row.addStretch(1)
        self._play_btn = QPushButton("Play")
        self._pause_btn = QPushButton("Pause")
        self._reset_btn = QPushButton("Reset")
        for btn in (self._play_btn, self._pause_btn, self._reset_btn):
            btn.setStyleSheet(PRIMARY_BTN_QSS)
            btn.setMinimumWidth(100)
        self._pause_btn.setStyleSheet(WARNING_BTN_QSS)
        self._reset_btn.setStyleSheet(DANGER_BTN_QSS)
        control_row.addWidget(self._play_btn)
        control_row.addWidget(self._pause_btn)
        control_row.addWidget(self._reset_btn)
        control_row.addSpacing(14)
        speed_label = QLabel("Speed")
        speed_label.setStyleSheet(f"color:{TEXT_HINT};")
        self._speed = QSlider(Qt.Horizontal)
        self._speed.setRange(1, 10)
        self._speed.setValue(5)
        self._speed.setFixedWidth(200)
        self._speed_input = QLineEdit("5")
        self._speed_input.setAlignment(Qt.AlignCenter)
        self._speed_input.setFixedWidth(60)
        control_row.addWidget(speed_label)
        control_row.addWidget(self._speed)
        control_row.addWidget(self._speed_input)
        speed_unit = QLabel("s")
        speed_unit.setStyleSheet(f"color:{TEXT_HINT};")
        control_row.addWidget(speed_unit)
        control_row.addStretch(1)
        diagram_layout.addLayout(control_row)
        self._workflow_layout.addWidget(self._diagram_box)
        layout.addWidget(self._workflow_box)

        example_box = QGroupBox("Simplified Example (4-bit nibbles)")
        example_layout = QVBoxLayout(example_box)
        self._example_scroll = QScrollArea()
        self._example_scroll.setWidgetResizable(True)
        self._example_scroll.setFrameShape(QFrame.NoFrame)
        self._example_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._example_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._example_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._example_scroll.setMinimumHeight(0)
        self._example_scroll.setStyleSheet(
            "QScrollArea { background: transparent; } QScrollArea::viewport { background: transparent; }"
        )
        self._example_scroll.setAutoFillBackground(False)
        self._example_scroll.viewport().setAutoFillBackground(False)
        example_content = QWidget()
        example_content.setAutoFillBackground(False)
        example_content.setAttribute(Qt.WA_TranslucentBackground, True)
        example_content.setStyleSheet("background: transparent;")
        example_content_layout = QVBoxLayout(example_content)
        example_content_layout.setContentsMargins(0, 0, 0, 0)
        self._example_hint = QLabel(
            "Exercise: compute each block using the rule above, then confirm the final result."
        )
        self._example_hint.setWordWrap(True)
        self._example_hint.setStyleSheet(f"color:{TEXT_HINT};")
        example_content_layout.addWidget(self._example_hint)
        self._example_given = _mono_label("")
        self._example_final = _mono_label("")
        example_content_layout.addWidget(self._example_given)
        self._example_mapping_labels: list[QLabel] = []
        self._example_mapping_container = QWidget()
        self._example_mapping_layout = QVBoxLayout(self._example_mapping_container)
        self._example_mapping_layout.setSpacing(2)
        self._example_mapping_layout.setContentsMargins(0, 0, 0, 0)
        self._example_mapping_spacer = None
        example_content_layout.addWidget(self._example_mapping_container)
        self._example_diagrams_container = QWidget()
        self._example_diagrams_layout = QBoxLayout(QBoxLayout.TopToBottom, self._example_diagrams_container)
        self._example_diagrams_layout.setSpacing(8)
        self._example_diagrams_layout.setContentsMargins(0, 0, 0, 0)
        example_content_layout.addWidget(self._example_diagrams_container)
        example_content_layout.addWidget(self._example_final)
        self._example_scroll.setWidget(example_content)
        example_layout.addWidget(self._example_scroll, 1)
        layout.addWidget(example_box)

        self._steps_widgets: list[QLabel] = []
        self._step_nums: list[QLabel] = []
        self._step_rows: list[QWidget] = []
        self._active_step = 0
        self._example_steps: list[ExampleStep] = []
        self._example_diagrams: list[ExampleDiagramWidget] = []
        self._speed_seconds = 5
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance_step)

        self._play_btn.clicked.connect(self._play)
        self._pause_btn.clicked.connect(self._pause)
        self._reset_btn.clicked.connect(self._reset)
        self._speed.valueChanged.connect(self._on_speed_slider)
        self._speed_input.editingFinished.connect(self._on_speed_input)
        self._enc_btn.toggled.connect(self._on_encrypt_toggle)

        self._set_workflow_steps(self._workflow_encrypt)
        self._update_example(True)
        self._apply_speed_seconds(5)
        self._update_controls()

    def _on_encrypt_toggle(self, checked: bool) -> None:
        self._diagram_widget.set_encrypt(checked)
        self._set_workflow_steps(self._workflow_encrypt if checked else self._workflow_decrypt)
        self._update_example(checked)
        self._reset()

    def _set_workflow_steps(self, steps: list[str]) -> None:
        for row in self._step_rows:
            self._steps_layout.removeWidget(row)
            row.setParent(None)
            row.deleteLater()
        self._steps_widgets.clear()
        self._step_nums.clear()
        self._step_rows.clear()
        for idx, step in enumerate(steps, start=1):
            row = QHBoxLayout()
            row.setContentsMargins(6, 2, 6, 2)
            num = QLabel(f"{idx}.")
            num.setStyleSheet(f"color:{TEXT_DARK}; font-weight:700;")
            text = ClickableLabel(step, idx - 1, self._on_step_clicked)
            text.setWordWrap(True)
            text.setStyleSheet(f"color:{TEXT_HINT};")
            row.addWidget(num)
            row.addWidget(text, 1)
            wrapper = QWidget()
            wrapper.setLayout(row)
            self._steps_layout.addWidget(wrapper)
            self._steps_widgets.append(text)
            self._step_nums.append(num)
            self._step_rows.append(wrapper)
        self._highlight_step(0)
        self._diagram_widget.set_active_step(0)

    def _highlight_step(self, index: int) -> None:
        for idx, label in enumerate(self._steps_widgets):
            if idx == index:
                self._step_rows[idx].setStyleSheet(
                    f"background:{BLUE}; border:1px solid {BLUE}; border-radius:6px;"
                )
                label.setStyleSheet("color:white; font-weight:700;")
                self._step_nums[idx].setStyleSheet("color:white; font-weight:700;")
            else:
                self._step_rows[idx].setStyleSheet("")
                label.setStyleSheet(f"color:{TEXT_HINT};")
                self._step_nums[idx].setStyleSheet(f"color:{TEXT_DARK}; font-weight:700;")

    def _update_example(self, encrypt: bool) -> None:
        payload = self._example_builder(encrypt)
        self._example_steps = payload.steps
        for diagram in self._example_diagrams:
            self._example_diagrams_layout.removeWidget(diagram)
            diagram.deleteLater()
        self._example_diagrams.clear()
        self._example_diagrams_layout.setDirection(QBoxLayout.TopToBottom)
        if self._mode in (MODES[1], MODES[2]):
            diagram = ExampleDiagramWidget(self._mode)
            diagram.set_encrypt(encrypt)
            diagram.set_steps(self._example_steps)
            diagram.set_step_index(0)
            self._example_diagrams_layout.addWidget(diagram)
            self._example_diagrams.append(diagram)
        else:
            for step in self._example_steps:
                diagram = ExampleDiagramWidget(self._mode)
                diagram.set_encrypt(encrypt)
                diagram.set_steps([step])
                diagram.set_step_index(0)
                self._example_diagrams_layout.addWidget(diagram)
                self._example_diagrams.append(diagram)
        self._example_given.setText(f"Given: {payload.given_line}")
        for label in self._example_mapping_labels:
            self._example_mapping_layout.removeWidget(label)
            label.deleteLater()
        self._example_mapping_labels.clear()
        if self._example_mapping_spacer is not None:
            self._example_mapping_layout.removeItem(self._example_mapping_spacer)
            self._example_mapping_spacer = None
        for line in payload.mapping_questions:
            label = _mono_label(line)
            label.setText(f"- {line}")
            self._example_mapping_layout.addWidget(label)
            self._example_mapping_labels.append(label)
        self._example_final.setText(f"Result:\n- {payload.final_line}")

    def _play(self) -> None:
        self._timer.start()
        self._update_controls()

    def _pause(self) -> None:
        self._timer.stop()
        self._update_controls()

    def _reset(self) -> None:
        self._timer.stop()
        self._active_step = 0
        self._highlight_step(self._active_step)
        self._diagram_widget.set_active_step(self._active_step)
        self._update_controls()

    def _advance_step(self) -> None:
        if not self._steps_widgets:
            return
        self._active_step = (self._active_step + 1) % len(self._steps_widgets)
        self._highlight_step(self._active_step)
        self._diagram_widget.set_active_step(self._active_step)

    def _on_step_clicked(self, index: int) -> None:
        self._pause()
        self._active_step = index
        self._highlight_step(self._active_step)
        self._diagram_widget.set_active_step(self._active_step)

    def _update_timer_interval(self) -> None:
        self._timer.setInterval(int(self._speed_seconds * 1000))

    def _apply_speed_seconds(self, seconds: int) -> None:
        seconds = max(1, min(10, seconds))
        self._speed_seconds = seconds
        if self._speed.value() != seconds:
            self._speed.blockSignals(True)
            self._speed.setValue(seconds)
            self._speed.blockSignals(False)
        if self._speed_input.text() != str(seconds):
            self._speed_input.blockSignals(True)
            self._speed_input.setText(str(seconds))
            self._speed_input.blockSignals(False)
        self._update_timer_interval()

    def _on_speed_slider(self, value: int) -> None:
        self._apply_speed_seconds(value)

    def _on_speed_input(self) -> None:
        text = self._speed_input.text().strip()
        try:
            seconds = int(text)
        except ValueError:
            self._speed_input.setText(str(self._speed_seconds))
            return
        self._apply_speed_seconds(seconds)

    def _update_controls(self) -> None:
        running = self._timer.isActive()
        self._play_btn.setEnabled(not running)
        self._pause_btn.setEnabled(running)



class PaddingTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._encrypt = True
        self._padding_name: PaddingMode = PADDING_MODES[0]
        self._padding_modes: list[PaddingMode] = list(PADDING_MODES)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        desc = QLabel(
            "Padding fills the last block so the block cipher can process whole blocks. "
            "On decrypt, the padding is validated and removed."
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{TEXT_HINT}; font-weight:700;")
        desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.setAlignment(Qt.AlignTop)
        layout.addWidget(desc)

        workflow_box = QGroupBox("Workflow")
        self._workflow_layout = QVBoxLayout(workflow_box)
        self._workflow_layout.setSpacing(6)
        workflow_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        workflow_box.setMaximumHeight(PADDING_WORKFLOW_MAX_HEIGHT)

        steps_row = QHBoxLayout()
        steps_row.setSpacing(12)
        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.setSpacing(6)
        steps_row.addWidget(self._steps_container, 1)

        pros_box = QGroupBox("Benefits / Drawbacks of Using Padding and Unpadding Schemes")
        pros_layout = QVBoxLayout(pros_box)
        pros_table = QTableWidget(3, 2)
        pros_table.setHorizontalHeaderLabels(["Benefits", "Drawbacks"])
        pros_table.verticalHeader().setVisible(False)
        pros_table.setEditTriggers(QTableWidget.NoEditTriggers)
        pros_table.setSelectionMode(QTableWidget.NoSelection)
        pros_table.setWordWrap(True)
        pros_table.setTextElideMode(Qt.ElideNone)
        pros_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        pros_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        pros_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        pros_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        pros_table.setStyleSheet(
            f"QTableWidget {{ background: transparent; gridline-color:{PANEL_BORDER}; }} "
            f"QTableWidget::item {{ background:{TITLE_BG}; }} "
            f"QHeaderView::section {{ background:{PANEL_BG}; border:1px solid {PANEL_BORDER}; font-weight:700; }}"
        )
        pros_table.horizontalHeader().setStretchLastSection(False)
        pros_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        pros_table.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        pros_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        rows = [
            (
                "Enables block based modes that require full blocks (especially ECB and CBC) to handle "
                "arbitrary length messages by extending the plaintext to a valid block length.",
                "Adds length overhead, up to one full extra block, because padding is typically added even "
                "when the input is already block aligned.",
            ),
            (
                "With a well defined padding rule, the original message can be recovered unambiguously "
                "after decryption by removing the padding.",
                "Incorrect error handling during unpadding can leak padding validity and enable padding "
                "oracle attacks in CBC style constructions.",
            ),
            (
                "Enforces block alignment so the mode definitions apply cleanly to every block, including "
                "the final block.",
                "Padding is unnecessary for stream like modes such as CTR, where the plaintext "
                "does not need to be a multiple of the block size.",
            ),
        ]
        for row, (pro, con) in enumerate(rows):
            pros_table.setItem(row, 0, _table_item(pro))
            pros_table.setItem(row, 1, _table_item(con))
        pros_table.resizeRowsToContents()
        QTimer.singleShot(
            0,
            lambda t=pros_table: _shrink_table(
                t,
                max_height=PADDING_PROS_TABLE_HEIGHT,
                min_height=PADDING_PROS_TABLE_HEIGHT,
            ),
        )
        pros_layout.addWidget(pros_table, 1)
        steps_row.addWidget(pros_box, 1)
        self._workflow_layout.addLayout(steps_row)

        layout.addWidget(workflow_box, 0)

        example_box = QGroupBox("Example")
        example_layout = QVBoxLayout(example_box)
        example_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._example_container = QWidget()
        self._example_layout = QVBoxLayout(self._example_container)
        self._example_layout.setSpacing(4)
        self._example_layout.setContentsMargins(0, 0, 0, 0)
        self._example_layout.addStretch(1)
        example_layout.addWidget(self._example_container)
        self._bytes_row = QHBoxLayout()
        example_layout.addLayout(self._bytes_row)
        layout.addWidget(example_box, 1)

        self._step_labels: list[QLabel] = []
        self._step_nums: list[QLabel] = []
        self._step_rows: list[QWidget] = []
        self._example_header_labels: list[QLabel] = []
        self._example_step_labels: list[QLabel] = []
        self._example_state: tuple[list[int], list[int], list[int]] | None = None
        self._active_step = 0

        self._refresh_workflow()
        self._refresh_example()

    def set_padding_mode(self, name: PaddingMode) -> None:
        if name not in self._padding_modes:
            return
        self._padding_name = name
        self._refresh_workflow()
        self._refresh_example()

    def _refresh_workflow(self) -> None:
        for row in self._step_rows:
            self._steps_layout.removeWidget(row)
            row.setParent(None)
            row.deleteLater()
        self._step_labels.clear()
        self._step_nums.clear()
        self._step_rows.clear()
        self._active_step = 0
        steps = self._workflow_encrypt() if self._encrypt else self._workflow_decrypt()
        for idx, step in enumerate(steps, start=1):
            row = QHBoxLayout()
            row.setContentsMargins(6, 2, 6, 2)
            num = QLabel(f"{idx}.")
            num.setStyleSheet(f"color:{TEXT_DARK}; font-weight:700;")
            text = ClickableLabel(step, idx - 1, self._on_step_clicked)
            text.setWordWrap(True)
            text.setStyleSheet(f"color:{TEXT_HINT};")
            row.addWidget(num)
            row.addWidget(text, 1)
            wrapper = QWidget()
            wrapper.setLayout(row)
            self._steps_layout.addWidget(wrapper)
            self._step_labels.append(text)
            self._step_nums.append(num)
            self._step_rows.append(wrapper)
        self._highlight_step(0)
        self._update_example_highlight(0)

    def _workflow_encrypt(self) -> list[str]:
        if self._padding_name == PADDING_MODES[0]:
            return [
                "Compute the padding length as 16 minus the remainder of the message length divided by 16. "
                "If the message length is already a multiple of 16, add a full padding block (16 bytes of 0x10).",
                "Append pad length as the value of every added byte.",
                "Encrypt the padded blocks.",
            ]
        if self._padding_name == PADDING_MODES[1]:
            return [
                "Compute the padding length for a 16-byte block and append zeros.",
                "Write the pad length as the final byte.",
                "Encrypt the padded blocks.",
            ]
        return [
            "Append 0x80 as a marker byte.",
            "Fill with 0x00 until the length is a multiple of the block size (16 for AES). "
            "If the input is already block aligned, append a full new block starting with 0x80 then zeros.",
            "Encrypt the padded blocks.",
        ]

    def _workflow_decrypt(self) -> list[str]:
        if self._padding_name == PADDING_MODES[0]:
            return [
                "Read the last byte to get the padding length for a 16-byte block.",
                "Verify all pad bytes have that value.",
                "Strip the padding bytes.",
            ]
        if self._padding_name == PADDING_MODES[1]:
            return [
                "Read the last byte to get the padding length for a 16-byte block.",
                "Verify previous pad bytes are zero.",
                "Strip the padding bytes.",
            ]
        return [
            "Scan from the end for the 0x80 marker.",
            "Verify bytes after the marker are 0x00 up to 16 bytes total.",
            "Strip the marker and zeros.",
        ]

    def _refresh_example(self) -> None:
        block_size = 16
        data = [0x41, 0x42, 0x43]
        pad_len = block_size - (len(data) % block_size)
        added = []
        if self._padding_name == PADDING_MODES[0]:
            added = [pad_len] * pad_len
        elif self._padding_name == PADDING_MODES[1]:
            added = [0] * (pad_len - 1) + [pad_len]
        else:
            added = [0x80] + [0x00] * (pad_len - 1)

        padded = data + added
        self._example_state = (data, added, padded)

        header_lines = [
            f"Block size: {block_size} bytes",
            f"Data bytes: {', '.join(f'0x{b:02X}' for b in data)}",
            f"Padding mode: {self._padding_name}",
        ]
        padded_line = ", ".join(f"0x{b:02X}" for b in padded)
        step_lines = [
            f"Added bytes: {', '.join(f'0x{b:02X}' for b in added)}",
            f"Padded block: {padded_line}",
            "Result: padded plaintext" if self._encrypt else "Result: removed padding",
        ]

        for label in self._example_header_labels + self._example_step_labels:
            self._example_layout.removeWidget(label)
            label.deleteLater()
        self._example_header_labels.clear()
        self._example_step_labels.clear()
        for line in header_lines:
            label = _mono_label(line)
            self._example_layout.insertWidget(self._example_layout.count() - 1, label)
            self._example_header_labels.append(label)
        for line in step_lines:
            label = _mono_label(line)
            self._example_layout.insertWidget(self._example_layout.count() - 1, label)
            self._example_step_labels.append(label)
        self._update_example_highlight(self._active_step)
        self._update_bytes_row(self._active_step)

    def _update_bytes_row(self, index: int) -> None:
        if self._example_state is None:
            return
        data, added, padded = self._example_state
        last_step = max(len(self._example_step_labels) - 1, 0)

        while self._bytes_row.count():
            item = self._bytes_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        def add_byte(byte: int, highlighted: bool, removed: bool = False) -> None:
            label = QLabel(f"{byte:02X}")
            label.setAlignment(Qt.AlignCenter)
            label.setFixedWidth(36)
            label.setStyleSheet(
                "background:{bg}; border:1px solid {border}; border-radius:6px; padding:4px; font-weight:700;"
                "color:{color};".format(
                    bg=PANEL_BG if highlighted else TITLE_BG,
                    border=DANGER_HOVER if removed else PANEL_BORDER,
                    color=TEXT_DARK,
                )
            )
            label.setFont(QFont("Consolas", 10))
            self._bytes_row.addWidget(label)

        if self._encrypt:
            if index < last_step:
                for byte in data:
                    add_byte(byte, highlighted=False)
            else:
                for byte in data:
                    add_byte(byte, highlighted=False)
                for byte in added:
                    add_byte(byte, highlighted=True)
        else:
            if index < last_step:
                for byte in padded:
                    add_byte(byte, highlighted=False)
            else:
                for idx, byte in enumerate(padded):
                    removed = idx >= len(data)
                    add_byte(byte, highlighted=removed, removed=removed)

        self._bytes_row.addStretch(1)

    def _highlight_step(self, index: int) -> None:
        for idx, label in enumerate(self._step_labels):
            if idx == index:
                self._step_rows[idx].setStyleSheet(
                    f"background:{BLUE}; border:1px solid {BLUE}; border-radius:6px;"
                )
                label.setStyleSheet("color:white; font-weight:700;")
                self._step_nums[idx].setStyleSheet("color:white; font-weight:700;")
            else:
                self._step_rows[idx].setStyleSheet("")
                label.setStyleSheet(f"color:{TEXT_HINT};")
                self._step_nums[idx].setStyleSheet(f"color:{TEXT_DARK}; font-weight:700;")

    def _on_step_clicked(self, index: int) -> None:
        self._active_step = index
        self._highlight_step(self._active_step)
        self._update_example_highlight(self._active_step)

    def _update_example_highlight(self, index: int) -> None:
        for idx, label in enumerate(self._example_step_labels):
            label.setVisible(idx <= index)
            if idx == index:
                label.setStyleSheet(
                    f"color:{TEXT_DARK}; font-weight:700; background:{TITLE_BG}; "
                    f"border:1px solid {PANEL_BORDER}; border-radius:6px; padding:4px;"
                )
            else:
                label.setStyleSheet(f"color:{TEXT_DARK};")
        self._update_bytes_row(index)


class SizeHintStack(QStackedWidget):
    def sizeHint(self) -> QSize:
        current = self.currentWidget()
        if current is None:
            return super().sizeHint()
        return current.sizeHint()

    def minimumSizeHint(self) -> QSize:
        current = self.currentWidget()
        if current is None:
            return super().minimumSizeHint()
        return current.minimumSizeHint()


class AdaptiveScrollArea(QScrollArea):
    def __init__(self, tolerance: int = 4) -> None:
        super().__init__()
        self._tolerance = tolerance

    def _update_policy(self) -> None:
        widget = self.widget()
        if widget is None:
            return
        hint_height = widget.sizeHint().height()
        viewport_height = self.viewport().height()
        if hint_height <= viewport_height + self._tolerance:
            self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        else:
            self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_policy()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_policy()


class ExplanationPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(GROUPBOX_QSS)

        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        self._scroll = AdaptiveScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.setStyleSheet(
            "QScrollArea { background: transparent; } QScrollArea::viewport { background: transparent; }"
        )
        self._scroll.setAutoFillBackground(False)
        self._scroll.viewport().setAutoFillBackground(False)

        content = QWidget()
        content.setAutoFillBackground(False)
        content.setAttribute(Qt.WA_TranslucentBackground, True)
        content.setStyleSheet("background: transparent;")
        self._outer_layout = QVBoxLayout(content)
        self._outer_layout.setContentsMargins(14, 14, 14, 14)
        self._outer_layout.setSpacing(12)
        self._outer_layout.setAlignment(Qt.AlignTop)

        self._title_label = QLabel("Explanation")
        self._title_label.setAlignment(Qt.AlignCenter)
        self._title_label.setStyleSheet(f"font-weight:900; font-size:18px; color:{TEXT_DARK};")
        self._title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._outer_layout.addWidget(self._title_label)

        self._info_label = QLabel(
            "Learn how ECB, CBC, CTR, and padding rules work.\n"
            "This page stays visual and concrete, focusing on steps, diagrams and small examples.\n"
            "In the mode of operation diagrams, Eₖ(·) denotes the block cipher encryption under key k, "
            "and Dₖ(·) denotes the corresponding inverse operation used for decryption.\n"
            "AES has a fixed block size of 16 bytes, but the simplified examples below use a reduced "
            "block size with 4 bit symbols (nibbles) to keep the computations readable."
        )
        self._info_label.setAlignment(Qt.AlignCenter)
        self._info_label.setWordWrap(True)
        self._info_label.setStyleSheet(
            f"color:{TEXT_HINT}; background:{TITLE_BG}; border:1px solid {PANEL_BORDER}; border-radius:10px; padding:10px;"
        )
        self._info_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._outer_layout.addWidget(self._info_label)

        nav_row = QHBoxLayout()
        nav_row.setSpacing(10)

        mode_box = QGroupBox("Modes of operation")
        mode_layout = QHBoxLayout(mode_box)
        mode_layout.setSpacing(6)
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._nav_buttons: list[QToolButton] = []
        for name in MODES:
            btn = QToolButton()
            btn.setText(name)
            btn.setCheckable(True)
            btn.setStyleSheet(TOGGLE_QSS)
            self._nav_group.addButton(btn)
            mode_layout.addWidget(btn)
            self._nav_buttons.append(btn)
        self._nav_buttons[0].setChecked(True)

        padding_box = QGroupBox("Padding schemes")
        padding_layout = QHBoxLayout(padding_box)
        padding_layout.setSpacing(6)
        self._padding_group = QButtonGroup(self)
        self._padding_group.setExclusive(True)
        self._padding_buttons: list[QToolButton] = []
        for name in PADDING_MODES:
            btn = QToolButton()
            btn.setText(name)
            btn.setCheckable(True)
            btn.setStyleSheet(TOGGLE_QSS)
            self._padding_group.addButton(btn)
            padding_layout.addWidget(btn)
            self._padding_buttons.append(btn)

        mode_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        nav_row.addWidget(mode_box, 1)
        or_wrapper = QWidget()
        or_layout = QVBoxLayout(or_wrapper)
        or_layout.setContentsMargins(6, 0, 6, 0)
        or_layout.addStretch(1)
        or_label = QLabel("OR")
        or_label.setAlignment(Qt.AlignCenter)
        or_label.setStyleSheet(f"color:{TEXT_HINT}; font-weight:700;")
        or_layout.addWidget(or_label)
        or_layout.addStretch(1)
        nav_row.addWidget(or_wrapper)
        padding_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        nav_row.addWidget(padding_box, 1)
        self._nav_container = QWidget()
        self._nav_container.setLayout(nav_row)
        self._nav_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._outer_layout.addWidget(self._nav_container)

        self._stack = SizeHintStack()
        self._stack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._outer_layout.addWidget(self._stack, 1)

        ecb_tab = ModeTab(
            MODES[0],
            f"{MODES[0]} processes each block independently. It is simple but reveals patterns because equal inputs "
            "produce equal outputs.",
            [
                "If padding is enabled, pad the plaintext first.",
                "Split plaintext into blocks of the cipher block size.",
                "Encrypt each block with the block cipher.",
                "Concatenate ciphertext blocks.",
            ],
            [
                "Split ciphertext into blocks of the cipher block size.",
                "Decrypt each block with the block cipher.",
                "Concatenate plaintext blocks.",
                "If padding is enabled, remove and validate padding.",
            ],
            [
                ("Simple block by block structure with errors staying limited to the affected block", "Identical plaintext blocks produce identical ciphertext blocks (deterministic)"),
                ("Fully parallelizable (blocks are independent)", "Leaks patterns across the message"),
                ("No IV or nonce required", "Blocks can be cut, pasted, reordered, or replayed without detection (no integrity)"),
            ],
            self._build_ecb_example,
        )

        cbc_tab = ModeTab(
            MODES[1],
            f"{MODES[1]} chains blocks: each plaintext block is XORed with the previous ciphertext (or IV) "
            "before encryption. This hides patterns but is sequential. "
            "This prevents repeated plaintext blocks from producing repeated ciphertext blocks.",
            [
                "If padding is enabled, pad the plaintext first.",
                "XOR the plaintext block with IV (first block) or previous ciphertext.",
                "Encrypt the XOR result with the block cipher.",
                "Emit ciphertext and repeat for the next block.",
            ],
            [
                "Decrypt the ciphertext block with the block cipher.",
                "XOR with IV (first block) or previous ciphertext.",
                "Recover plaintext and repeat.",
                "If padding is enabled, remove and validate padding.",
            ],
            [
                ("Repeated plaintext blocks produce different ciphertext blocks", "Encryption is sequential (cannot be parallelized)"),
                ("Hides patterns using chaining and an IV", "A ciphertext bit error damages this block and alters the next plaintext block"),
                ("Standardized and widely used construction", "IV must be unpredictable and never reused with the same key"),
                ("Decryption can be parallelized (blocks can be processed independently)", "No integrity unless combined with authentication"),
            ],
            self._build_cbc_example,
        )

        ctr_tab = ModeTab(
            MODES[2],
            f"{MODES[2]} turns a block cipher into a stream cipher by encrypting a counter and XORing with data.",
            [
                "Create a counter input (IV or nonce plus block index).",
                "Encrypt the counter with Eₖ to produce the keystream.",
                "XOR the keystream with the plaintext to get ciphertext.",
            ],
            [
                "Create the same counter input (IV or nonce plus block index).",
                "Encrypt the counter with Eₖ to produce the keystream.",
                "XOR the keystream with the ciphertext to recover plaintext.",
            ],
            [
                ("Fully parallelizable encryption and decryption (high throughput)", "Nonce||Counter must be unique per key"),
                ("No padding required (works on any length)", "Malleable: ciphertext bit flips cause plaintext bit flips"),
                ("Random access (seekable decryption per block)", "No built in authentication, must be combined with a MAC"),
            ],
            self._build_ctr_example,
        )

        padding_tab = PaddingTab()
        self._padding_tab = padding_tab

        self._stack.addWidget(ecb_tab)
        self._stack.addWidget(cbc_tab)
        self._stack.addWidget(ctr_tab)
        self._stack.addWidget(padding_tab)

        self._nav_group.buttonClicked.connect(self._on_nav_clicked)
        self._padding_group.buttonClicked.connect(self._on_padding_nav_clicked)
        self._stack.currentChanged.connect(self._stack.updateGeometry)
        self._stack.currentChanged.connect(self._sync_stack_height)
        self._stack.currentChanged.connect(self._scroll._update_policy)

        self._scroll.setWidget(content)
        self._scroll._update_policy()
        page_layout.addWidget(self._scroll, 1)
        self._sync_stack_height()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._sync_stack_height()

    def _sync_stack_height(self) -> None:
        current = self._stack.currentWidget()
        if current is None:
            return
        height = current.sizeHint().height()
        if current is self._padding_tab:
            margins = self._outer_layout.contentsMargins()
            spacing = self._outer_layout.spacing()
            header_height = (
                self._title_label.sizeHint().height()
                + self._info_label.sizeHint().height()
                + self._nav_container.sizeHint().height()
                + margins.top()
                + margins.bottom()
                + spacing * 3
            )
            available = self._scroll.viewport().height() - header_height
            if available > 0:
                max_height = max(height, available)
            else:
                max_height = height
            self._stack.setMinimumHeight(height)
            self._stack.setMaximumHeight(max_height)
            self._scroll._update_policy()
            return
        if height > 0:
            self._stack.setMinimumHeight(height)
            self._stack.setMaximumHeight(height)
        self._scroll._update_policy()

    def _example_common(self) -> tuple[list[int], int, list[int], list[int]]:
        e_map = [6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11]
        d_map = [0] * 16
        for idx, val in enumerate(e_map):
            d_map[val] = idx
        plaintext = [2, 5, 6]
        iv = 9
        return plaintext, iv, e_map, d_map

    def _build_ecb_example(self, encrypt: bool) -> ExamplePayload:
        plaintext, _, e_map, d_map = self._example_common()
        steps: list[ExampleStep] = []
        if encrypt:
            cipher = [e_map[p] for p in plaintext]
            for idx, value in enumerate(plaintext, start=1):
                steps.append(
                    ExampleStep(
                        input_label=f"P{idx}={_hex(value)}",
                        output_label=f"C{idx}={_hex(cipher[idx - 1])}",
                        cipher_label=f"Eₖ({_hex(value)})={_hex(cipher[idx - 1])}",
                    )
                )
            given = "P=(2,5,6)"
            mapping = [
                f"Eₖ(2)={_hex(e_map[2])}",
                f"Eₖ(5)={_hex(e_map[5])}",
                f"Eₖ(6)={_hex(e_map[6])}",
                f"Eₖ(0)={_hex(e_map[0])}",
                f"Eₖ(A)={_hex(e_map[10])}",
            ]
            final = "C=(" + ", ".join(_hex(c) for c in cipher) + ")"
        else:
            cipher = [e_map[p] for p in plaintext]
            plain = [d_map[c] for c in cipher]
            for idx, value in enumerate(cipher, start=1):
                steps.append(
                    ExampleStep(
                        input_label=f"C{idx}={_hex(value)}",
                        output_label=f"P{idx}={_hex(plain[idx - 1])}",
                        cipher_label=f"Dₖ({_hex(value)})={_hex(plain[idx - 1])}",
                    )
                )
            given = "C=(" + ", ".join(_hex(c) for c in cipher) + ")"
            mapping = [
                f"Dₖ({_hex(cipher[0])})={_hex(d_map[cipher[0]])}",
                f"Dₖ({_hex(cipher[1])})={_hex(d_map[cipher[1]])}",
                f"Dₖ({_hex(cipher[2])})={_hex(d_map[cipher[2]])}",
                f"Dₖ(0)={_hex(d_map[0])}",
                f"Dₖ(A)={_hex(d_map[10])}",
            ]
            final = "P=(" + ", ".join(_hex(p) for p in plain) + ")"
        return ExamplePayload(steps=steps, given_line=given, mapping_questions=mapping, final_line=final)

    def _build_cbc_example(self, encrypt: bool) -> ExamplePayload:
        plaintext, iv, e_map, d_map = self._example_common()
        steps: list[ExampleStep] = []
        if encrypt:
            x1 = _xor(plaintext[0], iv)
            c1 = e_map[x1]
            x2 = _xor(plaintext[1], c1)
            c2 = e_map[x2]
            x3 = _xor(plaintext[2], c2)
            c3 = e_map[x3]
            steps = [
                ExampleStep(
                    input_label=f"P1={_hex(plaintext[0])}",
                    output_label=f"C1={_hex(c1)}",
                    cipher_label=f"Eₖ({_hex(x1)})={_hex(c1)}",
                    iv_label=f"IV={_hex(iv)}",
                ),
                ExampleStep(
                    input_label=f"P2={_hex(plaintext[1])}",
                    output_label=f"C2={_hex(c2)}",
                    cipher_label=f"Eₖ({_hex(x2)})={_hex(c2)}",
                    iv_label=f"C1={_hex(c1)}",
                ),
                ExampleStep(
                    input_label=f"P3={_hex(plaintext[2])}",
                    output_label=f"C3={_hex(c3)}",
                    cipher_label=f"Eₖ({_hex(x3)})={_hex(c3)}",
                    iv_label=f"C2={_hex(c2)}",
                ),
            ]
            given = "P=(2,5,6), IV=9"
            mapping = [
                f"Eₖ({_hex(x1)})={_hex(e_map[x1])}",
                f"Eₖ({_hex(x2)})={_hex(e_map[x2])}",
                f"Eₖ({_hex(x3)})={_hex(e_map[x3])}",
                f"Eₖ(0)={_hex(e_map[0])}",
                f"Eₖ(A)={_hex(e_map[10])}",
            ]
            final = "C=(" + ", ".join(_hex(c) for c in [c1, c2, c3]) + ")"
        else:
            x1 = _xor(plaintext[0], iv)
            c1 = e_map[x1]
            x2 = _xor(plaintext[1], c1)
            c2 = e_map[x2]
            x3 = _xor(plaintext[2], c2)
            c3 = e_map[x3]
            p1 = _xor(d_map[c1], iv)
            p2 = _xor(d_map[c2], c1)
            p3 = _xor(d_map[c3], c2)
            steps = [
                ExampleStep(
                    input_label=f"C1={_hex(c1)}",
                    output_label=f"P1={_hex(p1)}",
                    cipher_label=f"Dₖ({_hex(c1)})={_hex(d_map[c1])}",
                    iv_label=f"IV={_hex(iv)}",
                ),
                ExampleStep(
                    input_label=f"C2={_hex(c2)}",
                    output_label=f"P2={_hex(p2)}",
                    cipher_label=f"Dₖ({_hex(c2)})={_hex(d_map[c2])}",
                    iv_label=f"C1={_hex(c1)}",
                ),
                ExampleStep(
                    input_label=f"C3={_hex(c3)}",
                    output_label=f"P3={_hex(p3)}",
                    cipher_label=f"Dₖ({_hex(c3)})={_hex(d_map[c3])}",
                    iv_label=f"C2={_hex(c2)}",
                ),
            ]
            given = "C=(" + ", ".join(_hex(c) for c in [c1, c2, c3]) + "), IV=9"
            mapping = [
                f"Dₖ({_hex(c1)})={_hex(d_map[c1])}",
                f"Dₖ({_hex(c2)})={_hex(d_map[c2])}",
                f"Dₖ({_hex(c3)})={_hex(d_map[c3])}",
                f"Dₖ(0)={_hex(d_map[0])}",
                f"Dₖ(A)={_hex(d_map[10])}",
            ]
            final = "P=(" + ", ".join(_hex(p) for p in [p1, p2, p3]) + ")"
        return ExamplePayload(steps=steps, given_line=given, mapping_questions=mapping, final_line=final)

    def _build_ctr_example(self, encrypt: bool) -> ExamplePayload:
        plaintext, iv, e_map, _ = self._example_common()
        ctr0 = iv
        s1 = e_map[ctr0]
        c1 = _xor(plaintext[0], s1)
        s2 = e_map[(iv + 1) & 0xF]
        c2 = _xor(plaintext[1], s2)
        s3 = e_map[(iv + 2) & 0xF]
        c3 = _xor(plaintext[2], s3)
        steps: list[ExampleStep] = []
        if encrypt:
            steps = [
                ExampleStep(
                    input_label=f"P1={_hex(plaintext[0])}",
                    output_label=f"C1={_hex(c1)}",
                    cipher_label=f"Eₖ({_hex(ctr0)})={_hex(s1)}",
                    counter_label=f"IV={_hex(ctr0)}",
                ),
                ExampleStep(
                    input_label=f"P2={_hex(plaintext[1])}",
                    output_label=f"C2={_hex(c2)}",
                    cipher_label=f"Eₖ({_hex((iv + 1) & 0xF)})={_hex(s2)}",
                    counter_label=f"IV+1={_hex((iv + 1) & 0xF)}",
                ),
                ExampleStep(
                    input_label=f"P3={_hex(plaintext[2])}",
                    output_label=f"C3={_hex(c3)}",
                    cipher_label=f"Eₖ({_hex((iv + 2) & 0xF)})={_hex(s3)}",
                    counter_label=f"IV+2={_hex((iv + 2) & 0xF)}",
                ),
            ]
            given = "P=(2,5,6), IV (counter start) = 9"
            mapping = [
                f"Eₖ(9)={_hex(e_map[9])}",
                f"Eₖ(A)={_hex(e_map[10])}",
                f"Eₖ(B)={_hex(e_map[11])}",
                f"Eₖ(0)={_hex(e_map[0])}",
                f"Eₖ(5)={_hex(e_map[5])}",
            ]
            final = "C=(" + ", ".join(_hex(c) for c in [c1, c2, c3]) + ")"
        else:
            p1 = _xor(c1, s1)
            p2 = _xor(c2, s2)
            p3 = _xor(c3, s3)
            steps = [
                ExampleStep(
                    input_label=f"C1={_hex(c1)}",
                    output_label=f"P1={_hex(p1)}",
                    cipher_label=f"Eₖ({_hex(ctr0)})={_hex(s1)}",
                    counter_label=f"IV={_hex(ctr0)}",
                ),
                ExampleStep(
                    input_label=f"C2={_hex(c2)}",
                    output_label=f"P2={_hex(p2)}",
                    cipher_label=f"Eₖ({_hex((iv + 1) & 0xF)})={_hex(s2)}",
                    counter_label=f"IV+1={_hex((iv + 1) & 0xF)}",
                ),
                ExampleStep(
                    input_label=f"C3={_hex(c3)}",
                    output_label=f"P3={_hex(p3)}",
                    cipher_label=f"Eₖ({_hex((iv + 2) & 0xF)})={_hex(s3)}",
                    counter_label=f"IV+2={_hex((iv + 2) & 0xF)}",
                ),
            ]
            given = "C=(" + ", ".join(_hex(c) for c in [c1, c2, c3]) + "), IV (counter start) = 9"
            mapping = [
                f"Eₖ(9)={_hex(e_map[9])}",
                f"Eₖ(A)={_hex(e_map[10])}",
                f"Eₖ(B)={_hex(e_map[11])}",
                f"Eₖ(0)={_hex(e_map[0])}",
                f"Eₖ(5)={_hex(e_map[5])}",
            ]
            final = "P=(" + ", ".join(_hex(p) for p in [p1, p2, p3]) + ")"
        return ExamplePayload(steps=steps, given_line=given, mapping_questions=mapping, final_line=final)

    def _on_nav_clicked(self, button: QToolButton) -> None:
        if self._padding_group.checkedButton() is not None:
            with QSignalBlocker(self._padding_group):
                self._padding_group.setExclusive(False)
                checked = self._padding_group.checkedButton()
                if checked:
                    checked.setChecked(False)
                self._padding_group.setExclusive(True)
        index = self._nav_buttons.index(button)
        self._stack.setCurrentIndex(index)

    def _on_padding_nav_clicked(self, button: QToolButton) -> None:
        if self._nav_group.checkedButton() is not None:
            with QSignalBlocker(self._nav_group):
                self._nav_group.setExclusive(False)
                checked = self._nav_group.checkedButton()
                if checked:
                    checked.setChecked(False)
                self._nav_group.setExclusive(True)
        self._stack.setCurrentIndex(3)
        self._padding_tab.set_padding_mode(button.text())
