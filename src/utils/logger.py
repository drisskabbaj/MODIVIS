import logging  # Needed for building the logger and defining levels/formatters/handlers (core logging system)
import sys  # Needed for sending console logs to stdout (console)
from logging.handlers import SysLogHandler  # Needed for native Linux syslog integration
import os # Needed fro checking log paths syslof

# -------------------------------------------------------------------------------------
#                                     COLORS
# -------------------------------------------------------------------------------------
# I colorize console logs using ANSI escape codes so INFO looks blue, SUCCESS green, etc.
# On Linux this is usually fine in terminals. In syslog I do not use colors.
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

# -------------------------------------------------------------------------------------
#                               CUSTOM LOG LEVELS
# -------------------------------------------------------------------------------------
# I picked 25 so it sits neatly between:
#   INFO = 20  <  SUCCESS = 25  <  WARNING = 30
# That way success feels more important than normal info, but definitely not a warning.
SUCCESS_LEVEL = 25
if not hasattr(logging, "SUCCESS"):
    logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

# -------------------------------------------------------------------------------------
#                           RUNTIME / GUI-TOGGLABLE SETTINGS
# -------------------------------------------------------------------------------------
LOG_VERBOSE_START_MESSAGES = False  # If True, I print "Starting..." banners elsewhere


# -------------------------------------------------------------------------------------
#                                   FORMATTER
# -------------------------------------------------------------------------------------
# Here I create a special formatter for the console:
#   - It adds colors depending on the log level.
#   - This makes logs easier to read for humans.
#
# Important:
#   - I only use colors for the console.
#   - Syslog/journald is not a terminal, so it must receive plain text only.
class ColorFormatter(logging.Formatter):
    # This dictionary maps log levels (numbers) to ANSI color codes.
    COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: BLUE,
        SUCCESS_LEVEL: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED,
    }

    def format(self, record):
        # The record object represents each single log message.
        # It contains information like:
        #   - record.levelno refers to numeric severity (20, 25, 30, etc)
        #   - record.levelname refers to text severity ("INFO", "SUCCESS", etc)
        #   - record.message refers to the actual message text.
        #   - record.name refers to logger name in my case it will be "MODIVIS".

        # I look at the log level number and choose the corresponding color.
        # If the level is unknown, I fall back to RESET that has no color for safety.
        color = self.COLORS.get(record.levelno, RESET)

        # super().format(record) builds the normal log line using the format string defined in the handler (timestamp, level name, logger name, message).
        # I wrap that text with:
        #   - a color prefix (to start coloring the terminal text)
        #   - a RESET suffix (to stop coloring so the next line is normal)
        #
        # Result:
        #   - Only THIS log line is colored.
        #   - Avoid that the terminal does not stay red/green by accident.
        return f"{color}{super().format(record)}{RESET}"


# -------------------------------------------------------------------------------------
#                              LOGGER INITIALIZATION
# -------------------------------------------------------------------------------------
# Here I create one application-level logger called MODIVIS.
# Using a fixed name helps filtering logs in syslog/journald.
#
# Linux logging model:
#   - Console output is automatically captured by systemd/journald when the app runs as a service.
#   - Syslog handler sends logs directly into the Linux logging pipeline.
#   - Log rotation is handled by the Linux OS, so I do not rotate logs inside the application.
logger = logging.getLogger("MODIVIS")

# I set the default minimum level to INFO.
# That means:
#   - INFO, SUCCESS, WARNING, ERROR, CRITICAL are shown
#   - DEBUG is hidden unless I change the level later
logger.setLevel(logging.INFO)

# I disable propagation to avoid log messages bubble up to the root logger.
# Without this, messages could appear twice if the root logger has handlers.
logger.propagate = False

# This guard ensures I do not attach handlers multiple times.
# This can happen if the module is imported more than once.
if not logger.handlers:

    # CONSOLE HANDLER
    # This handler prints logs to stdout aka terminal.
    # I attach the ColorFormatter so logs are cooler to eyes :)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        ColorFormatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S",)
    )
    logger.addHandler(console_handler)


# -------------------------------------------------------------------------------------
# UBUNTU LOGS vs WSL UBUNTU Checklists for internal system logs
#
# UBUNTU:
#   - systemd is PID 1 by default (journald)
#   - /dev/log usually exists, so SysLogHandler(address="/dev/log") works
#   - To view logs:
#       journalctl -b  # Show the journal logs from the current boot only 
#       journalctl -f  # Show live journal logs (new log lines appear as they happen)
#       journalctl -b --no-pager | grep MODIVIS #  Show the journal logs from the current boot only without opening the pager (no scroll UI), then filters and displays only lines that contain "MODIVIS".
#
# WSL UBUNTU:
#   - systemd may be off by default so: no journald, no /dev/log, no syslog history
#   - Enable systemd to get normal journald behavior:
#       sudo tee /etc/wsl.conf >/dev/null <<'EOF'
#       [boot]
#       systemd=true
#       EOF
#   - Then restart WSL
#   - Verify Changes with: ps -p 1 -o comm=   (should be "systemd")
#   - Verify socket:    ls -l /dev/log
#   - After that, use the same journalctl commands as above for "normal machines" Ubuntu.
#
# Retention settings and sizes-checks:
#   - Check size:  journalctl --disk-usage
#   - Cleanup:     sudo journalctl --vacuum-time=7d # to clean all last 7 days logs
#                 sudo journalctl --vacuum-size=200M # to clean 200mb of logs
#   - To modify our permanent policy:
#       sudo nano /etc/systemd/journald.conf
#       
#       Append content with:
#       [Journal]
#       Storage=persistent
#       SystemMaxUse=200M # allow only 200m size
#       MaxRetentionSec=14day # max 14 days logs allowed to remain
#
#       sudo systemctl restart systemd-journald # restart service
# -------------------------------------------------------------------------------------

    # SYSLOG HANDLER
    # This handler sends logs to the Linux syslog socket.
    # These logs are:
    #   - Collected by systemd-journald or rsyslog
    #   - Rotated by the OS automatically
    try:
        if os.path.exists("/dev/log"):
            syslog_handler = SysLogHandler(address="/dev/log")

            # Syslog does not understand/reformat colors, so I use a plain formatter here.
            syslog_handler.setFormatter(
                logging.Formatter("%(name)s: %(levelname)s: %(message)s")
            )

            logger.addHandler(syslog_handler)

    except Exception:
        # If syslog is not available (for ex:
        #   - running in a minimal container
        #   - running without /dev/log
        # I keep console logging to avoid crashing the application.
        pass

# DEBUG MODE SWITCH
# Toggles debug logging at runtime.
# Default is INFO (no debug). If enabled is equal True it will diplay also DEBUG Level.
def set_debug_enabled(enabled: bool) -> None:
    level = logging.DEBUG if enabled else logging.INFO
    logger.setLevel(level)
    for h in logger.handlers:
        h.setLevel(level)

set_debug_enabled(False)

# -------------------------------------------------------------------------------------
#                                    WRAPPERS
# -------------------------------------------------------------------------------------
# Friendly functions so the rest of my code does not touch logging internals.


def log_success(msg: str) -> None:
    # Log a green SUCCESS message (custom level between INFO and WARNING)
    logger.log(SUCCESS_LEVEL, msg)


def log_error(msg: str) -> None:
    # Log an ERROR message (red)
    logger.error(msg)


def log_warning(msg: str) -> None:
    # Log a WARNING message (yellow)
    logger.warning(msg)


def log_info(msg: str) -> None:
    # Log an INFO message (blue)
    logger.info(msg)


def log_debug(msg: str) -> None:
    # Log a DEBUG message (cyan)
    logger.debug(msg)


def should_log_starts() -> bool:
    # Return whether I want to print verbose "Starting..." messages elsewhere.
    return LOG_VERBOSE_START_MESSAGES
