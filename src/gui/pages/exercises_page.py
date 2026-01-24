from __future__ import annotations  # needed so type hints can reference classes that are defined later (avoids forward-reference issues)

import html  # needed to safely escape user-controlled or dynamic strings before inserting them into HTML

from PySide6.QtCore import Qt, QTimer  # needed for alignment constants, cursor hints and post-layout sizing
from PySide6.QtGui import QFont  # needed to set a monospace font for HEX and BIN displays
from PySide6.QtWidgets import (  # needed to build the Exercises UI (layouts, toggles, rich text view, input and buttons)
    QWidget,        # needed as the base widget for the page
    QVBoxLayout,    # needed for vertical stacking of the main sections
    QHBoxLayout,    # needed for horizontal rows (settings row and action buttons row)
    QLabel,         # needed for title, explanation texts, score display and feedback messages
    QGroupBox,      # needed for visually grouped sections (settings, exercise data, answer area)
    QToolButton,    # needed for toggle-style buttons (Normal/Hard)
    QButtonGroup,   # needed to make the level toggle buttons exclusive (only one selected at a time)
    QTextBrowser,   # needed to render the exercise description as rich HTML with scroll support
    QPlainTextEdit, # needed for the user answer input (simple multiline text without rich formatting)
    QPushButton,    # needed for actions (Check Answer, New Exercise, Reset Results)
    QSplitter,      # needed for resizable side-by-side panels (exercise vs answer)
)

from src.viewmodels.exercises_viewmodel import ExercisesViewModel  # needed for MVVM: UI requests new exercises and validates/submits answers via the viewmodel

# =========================
# Color palette
# =========================
BLUE = "#2f80ed"         # used for the primary theme (selected toggles, primary actions)
BLUE_HOVER = "#256bd6"   # used when hovering primary buttons
BLUE_PRESSED = "#1f5bb8" # used when pressing primary buttons

DANGER_HOVER = "#be123c"  # used for error feedback and negative emphasis (wrong answer, exceptions)

PANEL_BG = "#eef5ff"     # used as the background color of group boxes (light panel)
PANEL_BORDER = "#c7d7f2" # used as the border color of group boxes
TITLE_BG = "#ffffff"     # used as the background color behind title/info blocks
TEXT_HINT = "#334155"    # used for secondary helper text
TEXT_DARK = "#0f172a"    # used for primary text (titles and important labels)

SYSTEM_GREEN = "#16a34a" # used for success feedback and positive score color
SCORE_RED = "#be123c"    # used for negative score color

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
# Used for Normal and Hard level selection.

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
# Used for actions like Check Answer, New Exercise and Reset Results.

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
# QSS: Exercise view styling
# =========================
# Used to make QTextBrowser blend into the panel while keeping a subtle vertical scrollbar.

EXERCISE_VIEW_QSS = f"""
QTextBrowser {{
    background: transparent;
    border: none;
    padding: 6px;
    color: {TEXT_DARK};
}}
QTextBrowser viewport {{
    background: transparent;
}}
QTextBrowser QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0px;
}}
QTextBrowser QScrollBar::handle:vertical {{
    background: rgba(15, 23, 42, 0.25);
    border-radius: 5px;
    min-height: 24px;
}}
QTextBrowser QScrollBar::add-line:vertical, QTextBrowser QScrollBar::sub-line:vertical {{
    height: 0px;
}}
"""


class ExercisesPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.vm = ExercisesViewModel()

        self._build_ui()
        self._wire()
        self._new_exercise()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(12)
        self.setStyleSheet(GROUPBOX_QSS)

        title = QLabel("Exercises")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-weight:900; font-size:18px; color:{TEXT_DARK};")
        outer.addWidget(title)

        info = QLabel(
            "<div style='text-align:center;'>"
            "This page provides short guided exercises to practice <b>modes of operation</b>. "
            "Each task randomizes the <b>action</b> (Encrypt/Decrypt), the <b>mode</b> (ECB/CBC/CTR), and the <b>representation</b> (HEX/BIN).<br>"
            "Since AES is a <b>block cipher</b> with a <b>fixed 128-bit (16-byte) block size</b> "
            "(independent of whether the key is 128/192/256 bits) and its internal round computations are not practical to perform manually, <br>"
            "we model the primitive as a <b>keyed black-box permutation</b> <code>E<sub>K</sub>(·)</code>/<code>D<sub>K</sub>(·)</code> "
            "and provide the necessary outputs as a lookup table."
            "</div>"
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color:{TEXT_HINT}; background:{TITLE_BG}; border:1px solid {PANEL_BORDER}; border-radius:10px; padding:10px;"
        )
        outer.addWidget(info)

        explainer = QGroupBox("How it works")
        x_layout = QVBoxLayout(explainer)
        x_layout.setSpacing(6)

        explainer_text = QLabel(
            "<b>Symbols:</b> we work with 4-bit units (nibbles). In hexadecimal, symbols are <b>0..F</b>; "
            "in binary, symbols are <b>0000..1111</b>.<br>"
            "<b>Your Task:</b> solve the tasks by applying the mode rules and using the lookup table."
        )
        explainer_text.setWordWrap(True)
        explainer_text.setStyleSheet(f"color:{TEXT_HINT};")
        x_layout.addWidget(explainer_text)
        outer.addWidget(explainer)

        levels = QGroupBox("Level rules")
        l_layout = QHBoxLayout(levels)
        l_layout.setSpacing(10)

        level_left = QLabel(
            "<b>Normal</b><br>"
            "Wrong answer incurs no penalty<br>"
            "Good for practice"
        )
        level_right = QLabel(
            "<b>Hard</b><br>"
            "Wrong answer decreases the score by one<br>"
            "Correct answer increases the score by one"
        )
        level_left.setAlignment(Qt.AlignCenter)
        level_right.setAlignment(Qt.AlignCenter)
        level_left.setStyleSheet(f"color:{TEXT_DARK};")
        level_right.setStyleSheet(f"color:{TEXT_DARK};")
        l_layout.addWidget(level_left, 1)
        l_layout.addWidget(level_right, 1)
        outer.addWidget(levels)

        settings = QGroupBox("Exercise Settings")
        s_layout = QHBoxLayout(settings)
        s_layout.setSpacing(10)

        self.level_group = QButtonGroup(self)
        self.level_group.setExclusive(True)

        self.btn_normal = self._make_toggle("Normal", True)
        self.btn_hard = self._make_toggle("Hard", False)

        self.level_group.addButton(self.btn_normal)
        self.level_group.addButton(self.btn_hard)

        self.score_label = QLabel("Score: 0")
        self.score_label.setAlignment(Qt.AlignCenter)
        self.score_label.setStyleSheet(f"font-weight:900; color:{TEXT_DARK};")

        self.btn_reset = QPushButton("Reset Results")
        self.btn_reset.setStyleSheet(PRIMARY_BTN_QSS)

        s_layout.addWidget(self.btn_normal)
        s_layout.addWidget(self.btn_hard)
        s_layout.addStretch(1)
        s_layout.addWidget(self.score_label, 0, Qt.AlignCenter)
        s_layout.addStretch(1)
        s_layout.addWidget(self.btn_reset)
        outer.addWidget(settings)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(12)
        outer.addWidget(splitter, 1)

        exercise_box = QGroupBox("Current Exercise")
        e_layout = QVBoxLayout(exercise_box)
        e_layout.setSpacing(8)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)

        self.exercise_data = QTextBrowser()
        self.exercise_data.setFont(mono)
        self.exercise_data.setStyleSheet(EXERCISE_VIEW_QSS)
        self.exercise_data.setHtml(
            f"<div style='color:{TEXT_HINT}; font-family:Consolas,monospace;'>Exercise data will appear here.</div>"
        )
        self.exercise_data.viewport().setAutoFillBackground(False)
        e_layout.addWidget(self.exercise_data)

        exercise_actions = QHBoxLayout()
        exercise_actions.setAlignment(Qt.AlignCenter)

        self.btn_new = QPushButton("New Exercise")
        self.btn_new.setStyleSheet(PRIMARY_BTN_QSS)

        exercise_actions.addWidget(self.btn_new, 0, Qt.AlignCenter)
        e_layout.addLayout(exercise_actions)

        answer_box = QGroupBox("Your Answer")
        a_layout = QVBoxLayout(answer_box)
        a_layout.setSpacing(8)

        self.answer_input = QPlainTextEdit()
        self.answer_input.setFont(mono)
        self.answer_input.setPlaceholderText("Enter your answer.")
        a_layout.addWidget(self.answer_input)

        actions = QHBoxLayout()
        actions.setAlignment(Qt.AlignCenter)

        self.btn_check = QPushButton("Check Answer")
        self.btn_check.setStyleSheet(PRIMARY_BTN_QSS)

        self.feedback = QLabel("")
        self.feedback.setAlignment(Qt.AlignCenter)
        self.feedback.setStyleSheet(f"color:{TEXT_HINT};")

        actions.addWidget(self.btn_check, 0, Qt.AlignCenter)
        a_layout.addWidget(self.feedback)
        a_layout.addLayout(actions)

        splitter.addWidget(exercise_box)
        splitter.addWidget(answer_box)

        answer_box.setMinimumWidth(360)
        exercise_box.setMinimumWidth(480)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        def _init_split() -> None:
            w = splitter.width() or 1100
            splitter.setSizes([int(w * 0.65), int(w * 0.35)])

        QTimer.singleShot(0, _init_split)

        self.answer_input.setMinimumHeight(120)

        self._update_score_label()
        self._update_check_enabled()

    def _wire(self) -> None:
        self.level_group.buttonToggled.connect(self._on_level_changed)
        self.btn_reset.clicked.connect(self._reset_results)
        self.btn_new.clicked.connect(self._new_exercise)
        self.btn_check.clicked.connect(self._check_answer)

        # disable "Check Answer" when input is empty
        self.answer_input.textChanged.connect(self._update_check_enabled)

    def _make_toggle(self, text: str, checked: bool) -> QToolButton:
        b = QToolButton()
        b.setText(text)
        b.setCheckable(True)
        b.setChecked(checked)
        b.setCursor(Qt.PointingHandCursor)
        b.setStyleSheet(TOGGLE_QSS)
        return b

    def _on_level_changed(self, _btn, checked: bool) -> None:
        if not checked:
            return
        self.vm.set_level("HARD" if self.btn_hard.isChecked() else "NORMAL")

    def _reset_results(self) -> None:
        self.vm.reset()
        self._update_score_label()
        self._new_exercise()

    def _new_exercise(self) -> None:
        try:
            self.vm.new_exercise()
        except Exception as e:
            self.exercise_data.setHtml("")
            self.feedback.setText(
                f"<span style='color:{DANGER_HOVER}; font-weight:900;'>{html.escape(str(e))}</span>"
            )
            return

        self.answer_input.clear()
        self.feedback.setText("")
        self._render_exercise()
        self.answer_input.viewport().update()
        self._update_score_label()
        self._update_check_enabled()

    def _render_exercise(self) -> None:
        ex = self.vm.current_exercise()
        if not ex:
            self.exercise_data.setHtml("")
            return

        fmt = (getattr(ex, "fmt", None) or "HEX").upper()

        def section_title(text: str) -> str:
            return (
                f"<div style='margin:0 0 6px 0; color:{BLUE}; font-weight:900; text-decoration:underline;'>"
                f"{html.escape(text)}</div>"
            )

        show_iv = ex.mode in ("CBC", "CTR") and bool(ex.iv_hex)

        iv_row = ""
        if show_iv:
            iv_row = f"""
            <tr>
                <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">IV/Counter</td>
                <td style="padding:2px 0 2px 12px; vertical-align:top;">
                    <span style="font-weight:800;">{html.escape(ex.iv_hex)}</span>
                </td>
            </tr>
            """

        html_body = f"""
        <div style="font-family:Consolas,monospace; font-size:12px; color:{TEXT_DARK};">
          {section_title("GIVEN")}

          <table style="width:100%; table-layout:fixed; border-collapse:collapse; margin-bottom:10px;">
            <tr>
              <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">Mode</td>
              <td style="padding:2px 0 2px 12px; font-weight:700; vertical-align:top;">{html.escape(ex.mode)}</td>
            </tr>
            <tr>
              <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">Action</td>
              <td style="padding:2px 0 2px 12px; font-weight:700; vertical-align:top;">{html.escape(ex.action)}</td>
            </tr>
            <tr>
              <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">Representation</td>
              <td style="padding:2px 0 2px 12px; font-weight:700; vertical-align:top;">{html.escape(fmt)}</td>
            </tr>

            {iv_row}

            <tr>
              <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">{html.escape(ex.prompt_label)}</td>
              <td style="padding:2px 0 2px 12px; vertical-align:top;">
                <span style="font-weight:800;">{html.escape(ex.prompt_value)}</span>
              </td>
            </tr>
            <tr>
            <td style="width:190px; color:{TEXT_HINT}; padding:2px 0; vertical-align:top;">{html.escape(ex.oracle_label)}</td>
            <td style="padding:2px 0 2px 12px; vertical-align:top;">
                <div style="margin:0; display:block; white-space:pre-wrap; font-weight:700;">
                {html.escape(ex.oracle_table).replace("E_K", "E<sub>K</sub>").replace("D_K", "D<sub>K</sub>").replace(chr(10), "<br>")}
                </div>
            </td>
            </tr>
          </table>

          <div style="margin-top:12px;">{section_title("TASK")}</div>
          <ul style="margin:0; padding-left:18px; color:{TEXT_DARK};">
            <li>Compute {html.escape(ex.answer_label)}.</li>
            <li>Apply the mode rule and use the lookup table where needed.</li>
          </ul>
        </div>
        """
        self.exercise_data.setHtml(html_body)

        if fmt == "BIN":
            self.answer_input.setPlaceholderText("Write 4-bit groups. Example:\n(0000, 1111, 0000, 1111)")
        else:
            self.answer_input.setPlaceholderText("Write HEX symbols. Example:\n(F, F, 0, A)")

    def _update_check_enabled(self) -> None:
        txt = self.answer_input.toPlainText()
        self.btn_check.setEnabled(self.vm.can_check(txt))

    def _check_answer(self) -> None:
        ex = self.vm.current_exercise()
        if not ex:
            return

        user_answer = self.answer_input.toPlainText()
        res = self.vm.submit_answer(user_answer)

        if res.ok is None:
            self.feedback.setText(
                f"<span style='color:{DANGER_HOVER}; font-weight:900;'>{html.escape(res.message)}</span>"
            )
            return

        if res.ok:
            self.feedback.setText(
                f"<span style='color:{SYSTEM_GREEN}; font-weight:900;'>{html.escape(res.message)}</span>"
            )
        else:
            self.feedback.setText(
                f"<span style='color:{DANGER_HOVER}; font-weight:900;'>{html.escape(res.message)}</span>"
            )

        self._update_score_label()
        self._update_check_enabled()

    def _update_score_label(self) -> None:
        score = self.vm.score

        if score > 0:
            color = SYSTEM_GREEN
        elif score < 0:
            color = SCORE_RED
        else:
            color = TEXT_DARK

        self.score_label.setText(f"Score: {score}")
        self.score_label.setStyleSheet(f"font-weight:900; color:{color};")
