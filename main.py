from __future__ import annotations  # needed so type hints are treated like simple labels (aka. strings)

import os  # needed to control Qt platform behavior
import sys  # needed to read CLI args and to return the final exit code
import signal  # needed so Ctrl+C works in terminal even when Qt event loop is running

from src.utils.logger import log_error  # needed to log fatal error if the app crashes

# -------------------------------------------------------------------------------------
#                                   PLATFORM SAFEGUARD
# -------------------------------------------------------------------------------------
# Why?
#   - Avoids Wayland xdg-shell strict resizing (buffer mismatch crash).
#   - Forces Qt to use the stable X11 backend (xcb).
# -------------------------------------------------------------------------------------

try:
    os.environ["QT_QPA_PLATFORM"] = "xcb"
except Exception as e:
    log_error(f"event=env_setup_failed | module=main | func=bootstrap | key=QT_QPA_PLATFORM | value=xcb | error_type={type(e).__name__} | error={e}")
    raise


from PySide6.QtCore import Qt  # needed for global Qt attributes
from PySide6.QtWidgets import QApplication  # needed to create the Qt application

from src.gui.main_window import MainWindow  # needed to open the main window

# -------------------------------------------------------------------------------------
#                                   APP ENTRY POINT
# -------------------------------------------------------------------------------------
# Why?
#   - Starting point of the whole application.
#   - Creates Qt application object.
#   - Opens the main window.
# -------------------------------------------------------------------------------------

def main() -> None:
    # Make Ctrl+C work in terminal even with a Qt event loop
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # force non-native dialogs so global centering works consistently
    QApplication.setAttribute(Qt.AA_DontUseNativeDialogs, True)

    # Create Qt application object
    app = QApplication(sys.argv)

    # Set Fusion UI Style
    app.setStyle("Fusion")

    # Create and show the main window (tabs/pages are built inside MainWindow)
    win = MainWindow()
    win.showNormal()
    win.show()

    # Start the Qt event loop
    # This keeps the app alive and reacts to events
    # When the user closes the window, app.exec() returns an exit code
    sys.exit(app.exec())


if __name__ == "__main__":
    # Run the application.
    # If anything crashes before the GUI can show an error box we log it
    try:
        main()
    except Exception as e:
        log_error(f"event=app_crash | module=main | func=__main__ | error_type={type(e).__name__} | error={e}")
        raise
