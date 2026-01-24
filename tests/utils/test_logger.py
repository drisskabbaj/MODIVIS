import importlib
import logging

import src.utils.logger as logger


# (import safety) reloading the module should not multiply handlers
def test_logger_does_not_duplicate_handlers_on_reload():
    before = len(logger.logger.handlers)

    importlib.reload(logger)

    after = len(logger.logger.handlers)
    assert after == before


# SUCCESS level must exist and be named SUCCESS at level 25
def test_success_level_is_registered():
    assert logger.SUCCESS_LEVEL == 25
    assert logging.getLevelName(logger.SUCCESS_LEVEL) == "SUCCESS"


# ColorFormatter should add the right color prefix and RESET suffix for INFO
def test_color_formatter_colors_info_and_resets():
    fmt = logger.ColorFormatter("%(levelname)s|%(name)s|%(message)s")
    record = logging.LogRecord(
        name="AES-VisApp",
        level=logging.INFO,
        pathname="x",
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    out = fmt.format(record)

    assert out.startswith(logger.BLUE)
    assert out.endswith(logger.RESET)
    assert "INFO|AES-VisApp|hello" in out


# ColorFormatter should color SUCCESS level as GREEN and include SUCCESS Keyword in output
def test_color_formatter_colors_success_level_green():
    fmt = logger.ColorFormatter("%(levelname)s|%(message)s")
    record = logging.LogRecord(
        name="AES-VisApp",
        level=logger.SUCCESS_LEVEL,
        pathname="x",
        lineno=1,
        msg="ok",
        args=(),
        exc_info=None,
    )
    out = fmt.format(record)

    assert out.startswith(logger.GREEN)
    assert out.endswith(logger.RESET)
    assert "SUCCESS|ok" in out


# ColorFormatter should color WARNING as YELLOW
def test_color_formatter_colors_warning_yellow():
    fmt = logger.ColorFormatter("%(levelname)s|%(message)s")
    record = logging.LogRecord(
        name="AES-VisApp",
        level=logging.WARNING,
        pathname="x",
        lineno=1,
        msg="warn",
        args=(),
        exc_info=None,
    )
    out = fmt.format(record)

    assert out.startswith(logger.YELLOW)
    assert out.endswith(logger.RESET)
    assert "WARNING|warn" in out


# Logger should be configured with INFO level and propagate disabled (avoids duplicates)
def test_logger_configuration_level_and_propagation():
    assert logger.logger.level == logging.INFO
    assert logger.logger.propagate is False


# Wrapper log_success should call logger.log with SUCCESS_LEVEL and the same clear message
def test_log_success_calls_logger_log(monkeypatch):
    calls: list[tuple[int, str]] = []

    monkeypatch.setattr(logger.logger, "log", lambda lvl, msg: calls.append((lvl, msg)))

    logger.log_success("congrats :)!!")

    assert calls == [(logger.SUCCESS_LEVEL, "congrats :)!!")]


# Wrapper log_error should call logger.error with the same clear message
def test_log_error_calls_logger_error(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(logger.logger, "error", lambda msg: calls.append(msg))

    logger.log_error("error in last opereation!!")

    assert calls == ["error in last opereation!!"]


# Wrapper log_warning should call logger.warning with the same clear message
def test_log_warning_calls_logger_warning(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(logger.logger, "warning", lambda msg: calls.append(msg))

    logger.log_warning("warning!!")

    assert calls == ["warning!!"]


# Wrapper log_info should call logger.info with the same clear message
def test_log_info_calls_logger_info(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(logger.logger, "info", lambda msg: calls.append(msg))

    logger.log_info("info-exp")

    assert calls == ["info-exp"]


# Wrapper log_debug should call logger.debug with the same clear message
def test_log_debug_calls_logger_debug(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(logger.logger, "debug", lambda msg: calls.append(msg))

    logger.log_debug("debug-exp")

    assert calls == ["debug-exp"]


# should_log_starts should reflect the runtime flag value
def test_should_log_starts_reflects_flag(monkeypatch):
    monkeypatch.setattr(logger, "LOG_VERBOSE_START_MESSAGES", False)
    assert logger.should_log_starts() is False

    monkeypatch.setattr(logger, "LOG_VERBOSE_START_MESSAGES", True)
    assert logger.should_log_starts() is True
