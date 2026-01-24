from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings)

from PySide6.QtCore import Qt, QObject, QEvent, QTimer  # needed for tab bar elide flags and global event filter
from PySide6.QtGui import QPalette, QColor  # needed for tooltip palette colors
from PySide6.QtWidgets import (  # needed to build the main Qt window and tabs container
    QApplication,
    QToolTip,
    QMainWindow,
    QTabWidget,
    QDialog,
    QWidget,
)

from src.utils.logger import (
    log_info,
    log_success,
    log_warning,
    log_error,
    should_log_starts,
)  # needed to follow the app logging structure

from src.gui.pages.playground_page import PlaygroundPage  # needed to show the interactive encrypt/decrypt page
from src.gui.pages.explanation_page import ExplanationPage  # needed to show the learning/theory page
from src.gui.pages.exercises_page import ExercisesPage  # needed to show exercises page
from src.gui.pages.ascii import ASCIIPage  # needed to show ASCII page


# =========================
# Global tooltip styling
# =========================

# Core UI palette tokens used by tabs and tooltips
TITLE_BG = "#ffffff"
TEXT_DARK = "#0f172a"
PANEL_BORDER = "#c7d7f2"
TAB_BG = "#e6ecf7"
TAB_BG_HOVER = "#d6e1f5"
TAB_BG_ACTIVE = "#2f80ed"
TAB_TEXT = "#0f172a"
TAB_TEXT_ACTIVE = "#ffffff"
TAB_BORDER = "#d4def2"
TAB_PANE_BG = "#f6f8fc"

# Global tooltip QSS applied at the QApplication level
TOOLTIP_QSS = f"""
QToolTip {{
    background: {TITLE_BG};
    color: {TEXT_DARK};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    padding: 6px 10px;
}}
"""

_TOOLTIP_STYLE_APPLIED = False  # global guard to avoid duplicate QSS/Palette updates


def _center_dialog_on(dialog: QWidget, anchor: QWidget | None) -> None:
    if dialog is None:
        return

    target = anchor
    if target is None or not target.isVisible():
        target = QApplication.activeWindow()

    if target is not None and target.isVisible():
        rect = dialog.frameGeometry()
        rect.moveCenter(target.frameGeometry().center())
        dialog.move(rect.topLeft())
        return

    screen = dialog.screen()
    if screen is not None:
        rect = dialog.frameGeometry()
        rect.moveCenter(screen.availableGeometry().center())
        dialog.move(rect.topLeft())


class _DialogCenteringFilter(QObject):
    def __init__(self, anchor: QWidget) -> None:
        super().__init__()
        self._anchor = anchor

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Show, QEvent.Resize) and isinstance(obj, QDialog):
            QTimer.singleShot(0, lambda: _center_dialog_on(obj, self._anchor))
        return False


def _apply_global_tooltip_style_once() -> None:
    # Why?
    #   - Tooltips are global UI behavior (QToolTip).
    #   - Apply once for the entire app so all pages look consistent.
    label = "MainWindow"
    purpose = "apply_tooltip_style"
    global _TOOLTIP_STYLE_APPLIED
    if _TOOLTIP_STYLE_APPLIED:
        return

    app = QApplication.instance()
    if app is None:
        log_warning(
            f"Tooltip style skipped: QApplication instance missing | module=main_window | func=_apply_global_tooltip_style_once | label={label} | purpose={purpose}"
        )
        return

    try:
        # append (not wipe) existing app stylesheet
        app.setStyleSheet((app.styleSheet() or "") + TOOLTIP_QSS)

        # also set tooltip palette (global)
        pal = QToolTip.palette()
        pal.setColor(QPalette.ToolTipBase, QColor(TITLE_BG))
        pal.setColor(QPalette.ToolTipText, QColor(TEXT_DARK))
        QToolTip.setPalette(pal)
    except Exception as e:
        log_error(
            f"Tooltip style failed: {type(e).__name__}: {e} | module=main_window | func=_apply_global_tooltip_style_once | label={label} | purpose={purpose}"
        )
        raise

    _TOOLTIP_STYLE_APPLIED = True
    log_success(
        f"Tooltip style applied | module=main_window | func=_apply_global_tooltip_style_once | label={label} | purpose={purpose}"
    )


def _style_tabs(tab_widget: QTabWidget) -> None:
    # Why?
    #   - Centralizes tab styling so we keep UI look consistent.
    #   - Avoid repeating style logic in every page.
    label = "MainWindow"
    purpose = "style_tabs"
    if not isinstance(tab_widget, QTabWidget):
        log_error(
            f"Tab styling failed: invalid widget type | module=main_window | func=_style_tabs | type={type(tab_widget).__name__} | label={label} | purpose={purpose}"
        )
        raise TypeError("Tab styling failed: tab_widget must be a QTabWidget.")

    try:
        tab_widget.setStyleSheet(
            f"""
            QTabWidget::pane {{
                border: 1px solid {TAB_BORDER};
                border-top: 0;
                border-radius: 12px;
                background: {TAB_PANE_BG};
            }}
            QTabWidget::tab-bar {{
                alignment: center;
            }}
            QTabBar {{
                qproperty-expanding: 0;
            }}
            QTabBar::tab {{
                background: {TAB_BG};
                color: {TAB_TEXT};
                padding: 10px 18px;
                margin: 8px 6px 0 6px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                border: 1px solid {TAB_BORDER};
                border-bottom: 0;
                font-weight: 600;
            }}
            QTabBar::tab:hover {{
                background: {TAB_BG_HOVER};
            }}
            QTabBar::tab:selected {{
                background: {TAB_BG_ACTIVE};
                color: {TAB_TEXT_ACTIVE};
            }}
            """
        )
        tab_widget.tabBar().setExpanding(False)
        tab_widget.tabBar().setUsesScrollButtons(False)
        tab_widget.tabBar().setElideMode(Qt.TextElideMode.ElideRight)
    except Exception as e:
        log_error(
            f"Tab styling failed: {type(e).__name__}: {e} | module=main_window | func=_style_tabs | label={label} | purpose={purpose}"
        )
        raise


# -------------------------------------------------------------------------------------
#                                   MAIN WINDOW
# -------------------------------------------------------------------------------------
# Why?
#   - Main GUI window of the application.
#   - Holds tab bar and each tab is assigning a specific page.
#-------------------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        # Main app window initialization
        super().__init__()  # Initialize the QMainWindow base class

        # consistent log labels for this flow
        label = "MainWindow"
        purpose = "main_window.__init__"

        if should_log_starts():
            log_info(
                f"Main Window: init started | module=main_window | func=__init__ | label={label} | purpose={purpose}"
            )

        # apply global tooltip look once for the whole app
        _apply_global_tooltip_style_once()

        # center dialogs for the whole app (including message boxes)
        app = QApplication.instance()
        if app is None:
            log_warning(
                f"Dialog centering skipped: QApplication instance missing | module=main_window | func=__init__ | label={label} | purpose={purpose}"
            )
        else:
            self._dialog_center_filter = _DialogCenteringFilter(self)
            app.installEventFilter(self._dialog_center_filter)

        # Window title shown in the OS title bar
        self.setWindowTitle("MODIVIS")

        # Default window size on start
        self.resize(1400, 820)

        # Create the tabs widget and set it as the main content of the window
        try:
            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)
        except Exception as e:
            log_error(
                f"Main Window failed: QTabWidget init | module=main_window | func=__init__ | label={label} | purpose={purpose} | error={type(e).__name__}: {e}"
            )
            raise

        # Center tabs and apply a cleaner visual style
        _style_tabs(self.tabs)

        # Add each page as one tab
        try:
            self.tabs.addTab(PlaygroundPage(), "Playground")
            self.tabs.addTab(ExplanationPage(), "Explanation")
            self.tabs.addTab(ExercisesPage(), "Exercises")
            self.tabs.addTab(ASCIIPage(), "ASCII Table")
        except Exception as e:
            log_error(
                f"Main Window failed: tab initialization | module=main_window | func=__init__ | label={label} | purpose={purpose} | error={type(e).__name__}: {e}"
            )
            raise

        log_success(
            f"Main Window ready | module=main_window | func=__init__ | label={label} | purpose={purpose}"
        )
