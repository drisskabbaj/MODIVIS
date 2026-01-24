from __future__ import annotations  # needed so type hints can reference classes that are defined later (avoids forward-reference issues)

from PySide6.QtCore import Qt, QEvent  # needed for alignment flags, table item roles and hover leave detection
from PySide6.QtGui import QFont, QColor, QBrush, QPalette  # needed for monospace fonts, per-cell coloring and link palette override
from PySide6.QtWidgets import (  # needed to build the ASCII page UI (layouts, table, headers, dialogs)
    QWidget,         # needed as the base widget for the page
    QVBoxLayout,     # needed to stack title, info, details and the table section vertically
    QLabel,          # needed for title, info text and selection details display
    QGroupBox,       # needed to group the table area with a titled border
    QTableWidget,    # needed to render a 16x8 ASCII grid
    QTableWidgetItem,# needed to populate each ASCII cell with text and metadata
    QHeaderView,     # needed to stretch headers and keep the grid readable
    QMessageBox,     # needed to show errors when assets are missing or invalid
    QTextEdit,       # needed to access and style QMessageBox detailed text area
)

from src.viewmodels.ascii_table_viewmodel import (  # needed for MVVM: load ASCII entries from the viewmodel
    AsciiTableViewModel,  # needed to load the 7-bit ASCII table from assets
    AsciiEntry,           # needed for type hints and cached entry objects
)

# =========================
# Color palette
# =========================
BLUE = "#2f80ed"         # used for primary accents (links and selected values)
DANGER_HOVER = "#be123c" # used for warnings and control/del emphasis

PANEL_BG = "#eef5ff"     # used as the background color of group boxes
PANEL_BORDER = "#c7d7f2" # used as the border color of panels and table grid
TITLE_BG = "#ffffff"     # used as the background behind info blocks and printable cells
TEXT_HINT = "#334155"    # used for secondary helper text
TEXT_DARK = "#0f172a"    # used for primary text

SELECT_HOVER_BG = "#93c5fd"  # used for selected+hover so dark text stays readable

# =========================
# Cell category colors
# =========================
CONTROL_BG = "#fff1f2"  # used for control characters (DEC 0-31)
SPACE_BG = "#e0f2fe"    # used for SPACE (DEC 32)
DEL_BG = "#ffe4e6"      # used for DEL (DEC 127)

# =========================
# QSS: Group box styling
# =========================
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
# QSS: Table styling
# =========================
TABLE_QSS = f"""
QTableWidget {{
    background: {TITLE_BG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 10px;
    gridline-color: {PANEL_BORDER};
    outline: 0;
}}

QTableWidget::item {{
    padding: 6px;
}}

QTableWidget::item:hover {{
    background: #dbeafe; /* light blue hover */
}}

QTableWidget::item:selected {{
    background: {BLUE};
    color: white;
}}

QTableWidget::item:selected:hover {{
    background: {SELECT_HOVER_BG};
    color: {TEXT_DARK};
}}

QHeaderView::section {{
    background: {PANEL_BG};
    color: {TEXT_DARK};
    border: 1px solid {PANEL_BORDER};
    padding: 6px;
    font-weight: 800;
}}
"""


class ASCIIPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.vm = AsciiTableViewModel()

        self._by_dec: dict[int, AsciiEntry] = {}  # cache data so UI does not reload per click
        self._hovered: tuple[int, int] | None = None
        self._last_clicked: tuple[int, int] | None = None

        self._build_ui()
        self._load_and_render()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(10)

        self.setStyleSheet(GROUPBOX_QSS)

        # title
        title = QLabel("ASCII Table (0-127)")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-weight:900; font-size:18px; color:{TEXT_DARK};")
        outer.addWidget(title)

        # force link style inline
        link_style = f"color:{BLUE}; font-weight:800; text-decoration:none;"

        info = QLabel(
            "This page is a simplified <b>ASCII (0-127)</b> table made for learning and paper exercises: "
            "it helps quickly convert between <b>characters</b>, <b>DEC</b>, <b>HEX</b> and <b>BIN</b> "
            "when doing manual calculations.<br><br>"

            "<b><u>Color Key:</u></b> "
            f"<span style='background:{CONTROL_BG}; border:1px solid {PANEL_BORDER}; "
            f"padding:2px 8px; border-radius:8px; color:{DANGER_HOVER}; font-weight:900;'>"
            "Control (0-31)</span> "
            f"<span style='background:{SPACE_BG}; border:1px solid {PANEL_BORDER}; "
            "padding:2px 8px; border-radius:8px; color:#0f172a; font-weight:900;'>"
            "SPACE (32)</span> "
            f"<span style='background:{DEL_BG}; border:1px solid {PANEL_BORDER}; "
            f"padding:2px 8px; border-radius:8px; color:{DANGER_HOVER}; font-weight:900;'>"
            "DEL (127)</span> "
            f"<span style='background:{TITLE_BG}; border:1px solid {PANEL_BORDER}; "
            "padding:2px 8px; border-radius:8px; color:#0f172a; font-weight:900;'>"
            "Printable (33-126)</span>"
            "<br><br>"

            "Design inspiration: "
            f"<a href='https://www.ascii-code.com/ASCII/codechart' style='{link_style}'>"
            "https://www.ascii-code.com/ASCII/codechart</a><br>"
            "For further conversions (Unicode / special characters): "
            f"<a href='https://unicodelookup.com/' style='{link_style}'>"
            "https://unicodelookup.com/</a>"
        )
        info.setTextFormat(Qt.RichText)
        info.setOpenExternalLinks(True)
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignCenter)

        # keep palette override too
        pal = info.palette()
        pal.setColor(QPalette.Link, QColor(BLUE))
        pal.setColor(QPalette.LinkVisited, QColor(BLUE))
        info.setPalette(pal)

        info.setStyleSheet(
            f"""
            QLabel {{
                color:{TEXT_HINT};
                background:{TITLE_BG};
                border: 1px solid {PANEL_BORDER};
                border-radius: 10px;
                padding: 10px 12px;
            }}
            QLabel a:hover {{
                text-decoration: underline;
            }}
            """
        )
        outer.addWidget(info)

        # selected details
        self.details = QLabel("Click a cell to see: DEC / HEX / BIN")
        self.details.setAlignment(Qt.AlignCenter)
        self.details.setWordWrap(True)
        self.details.setStyleSheet(f"color:{TEXT_HINT};")
        self.details.setTextFormat(Qt.RichText)
        outer.addWidget(self.details)

        box = QGroupBox("ASCII (0-127)")
        outer.addWidget(box, 1)

        layout = QVBoxLayout(box)
        layout.setSpacing(10)

        self.table = QTableWidget(8, 16)
        self.table.setStyleSheet(TABLE_QSS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setSelectionBehavior(QTableWidget.SelectItems)
        self.table.setWordWrap(True)

        # headers like classic 16x8 ASCII table
        self.table.setHorizontalHeaderLabels([f"{i}\n0x{i:02X}" for i in range(16)])
        self.table.setVerticalHeaderLabels([f"{r * 16}\n0x{r * 16:02X}" for r in range(8)])

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)
        self.table.setFont(mono)

        header_font = QFont("Consolas")
        header_font.setStyleHint(QFont.Monospace)
        header_font.setPointSize(9)
        header_font.setBold(True)
        self.table.horizontalHeader().setFont(header_font)
        self.table.verticalHeader().setFont(header_font)

        # center header text
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.table.verticalHeader().setDefaultAlignment(Qt.AlignCenter)

        # hover + click
        self.table.setMouseTracking(True)
        self.table.cellEntered.connect(self._on_cell_hovered)
        self.table.viewport().installEventFilter(self)
        self.table.cellClicked.connect(self._on_cell_clicked)

        layout.addWidget(self.table)


    def _make_details_area_scrollable(self, box: QMessageBox) -> None:
        te = box.findChild(QTextEdit)
        if not te:
            return

        te.setLineWrapMode(QTextEdit.WidgetWidth)
        te.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        te.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

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


    def _load_and_render(self) -> None:
        try:
            entries = self.vm.load_ascii_7bit()
            self._by_dec = {e.dec: e for e in entries}

            bg_control = QBrush(QColor(CONTROL_BG))
            bg_space = QBrush(QColor(SPACE_BG))
            bg_del = QBrush(QColor(DEL_BG))
            fg_control = QBrush(QColor(DANGER_HOVER))

            # force printable cells to white
            bg_printable = QBrush(QColor(TITLE_BG))
            fg_printable = QBrush(QColor(TEXT_DARK))

            for r in range(8):
                for c in range(16):
                    dec = r * 16 + c
                    e = self._by_dec.get(dec)
                    if e is None:
                        continue

                    if e.dec == 32:
                        cell_top = "SPACE"
                    elif e.char:
                        cell_top = e.char
                    else:
                        cell_top = e.label

                    item = QTableWidgetItem(f"{cell_top}\n{e.dec}")
                    item.setTextAlignment(Qt.AlignCenter)

                    item.setToolTip(
                        f"DEC: {e.dec}\n"
                        f"HEX: 0x{e.hex}\n"
                        f"BIN: {e.bin}\n"
                        f"LABEL: {e.label or '-'}"
                    )

                    # default printable range (33-126)
                    item.setBackground(bg_printable)
                    item.setForeground(fg_printable)

                    # special categories
                    if e.dec < 32:
                        item.setBackground(bg_control)
                        item.setForeground(fg_control)
                    elif e.dec == 32:
                        item.setBackground(bg_space)
                        item.setForeground(fg_printable)
                    elif e.dec == 127:
                        item.setBackground(bg_del)
                        item.setForeground(fg_control)

                    # store original foreground color for hover restore
                    item.setData(Qt.UserRole, item.foreground().color().name())

                    self.table.setItem(r, c, item)

            self.table.setEnabled(True)

        except Exception as e:
            # keep page alive but disable interactions
            self._by_dec = {}
            self.table.setEnabled(False)
            self.details.setText(
                f"<b style='color:{DANGER_HOVER};'>ASCII table could not be loaded.</b><br>"
                "Please make sure <code>assets/samples/ascii_7bit.json</code> exists."
            )
            self._show_error("ASCII table could not be loaded.", str(e))


    def eventFilter(self, obj, event):
        if obj is self.table.viewport() and event.type() == QEvent.Type.Leave:
            self._clear_hover()
        return super().eventFilter(obj, event)

    def _clear_hover(self) -> None:
        if self._hovered is None:
            return
        r, c = self._hovered
        item = self.table.item(r, c)
        if item is not None and not item.isSelected():
            orig = item.data(Qt.UserRole)
            if isinstance(orig, str) and orig:
                item.setForeground(QBrush(QColor(orig)))
        self._hovered = None

    def _on_cell_hovered(self, row: int, col: int) -> None:
        if self._hovered is not None and self._hovered != (row, col):
            self._clear_hover()

        self._hovered = (row, col)
        item = self.table.item(row, col)
        if item is None:
            return


        if item.isSelected():
            return

        item.setForeground(QBrush(QColor(TEXT_DARK)))


    def _reset_details_hint(self) -> None:
        self.details.setText("Click a cell to see: DEC / HEX / BIN")

    def _on_cell_clicked(self, row: int, col: int) -> None:
        if self._last_clicked == (row, col):
            self.table.clearSelection()
            self._last_clicked = None
            self._reset_details_hint()
            return

        self._last_clicked = (row, col)

        dec = row * 16 + col
        e = self._by_dec.get(dec)
        if not e:
            self.details.setText("No data for this cell.")
            return

        shown = e.char if e.char else (e.label or "(none)")
        if e.dec == 32:
            shown = "SPACE"

        self.details.setText(
            "Selected: "
            f"<b><span style='color:{BLUE};'>{shown}</span></b>"
            "  |  DEC: "
            f"<b><span style='color:{BLUE};'>{e.dec}</span></b>"
            "  |  HEX: "
            f"<b><span style='color:{BLUE};'>0x{e.hex}</span></b>"
            "  |  BIN: "
            f"<b><span style='color:{BLUE};'>{e.bin}</span></b>"
        )
