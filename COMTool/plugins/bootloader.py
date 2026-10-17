#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bootloader.py —— COMTool 内置插件：APM32E103 BootLoader 上位机升级（Ymodem）

功能：把裸 APP bin 加上 32 字节固件头后，以标准 Ymodem（CRC-16 模式）
经串口发送给设备 BootLoader，实时显示进度、设备日志与升级结论。

上位机侧协议核心在 bootloader_ymodem.py（可离线自测，无需硬件）。

使用步骤：
  1. 左侧选择串口与 115200-8N1，点击 OPEN 连接；
  2. 选择固件文件、填写版本号等固件头参数，点击「开始升级」；
  3. 提示「等待设备邀请」时，按下下位机复位键：
        - 运行区无有效 APP  -> BootLoader 会持续发送 'C' 邀请；
        - 运行区有有效 APP  -> 复位后 3 秒窗口内发送 'C' 邀请。
  4. 传输完成后设备会打印 size/CRC32 与 UPDATE 结果，插件会与本地对拍。
"""
import os
import queue
import threading
import time
import zlib
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
                             QPushButton, QCheckBox, QLineEdit, QGroupBox, QFileDialog,
                             QProgressBar, QPlainTextEdit, QMessageBox)

try:
    from .base import Plugin_Base
    from . import bootloader_ymodem as ymo
    from Combobox import ComboBox
    from i18n import _
    from conn.base import ConnectionStatus
    from widgets import statusBar
except ImportError:
    from COMTool.i18n import _
    from COMTool.Combobox import ComboBox
    from COMTool.conn.base import ConnectionStatus
    from COMTool.widgets import statusBar
    from COMTool.plugins.base import Plugin_Base
    from COMTool.plugins import bootloader_ymodem as ymo


# ==================== 过程日志文案（code -> msgid，供 babel 提取） ====================
_LOG_MSG = {
    "wait_invite": _("Waiting for device invitation ('C') ... "
                     "If the device is not in upgrade mode yet, press its reset button now."),
    "invite_ok": _("Device invitation received."),
    "no_invite": _("No invitation received, the device is not in upgrade mode. "
                   "Please reset the device and try again."),
    "name_timeout": _("The filename packet was not confirmed (timeout). The device erases the whole "
                      "backup area first, which takes seconds. If it keeps timing out, please check "
                      "that the latest bootloader is flashed into the device."),
    "name_nak": _("The filename packet was rejected by the device (NAK). "
                  "Please check the firmware file and its size."),
    "name_can": _("The device aborted the transfer (CAN) while receiving the filename packet."),
    "name_unknown": _("The filename packet was not confirmed (unexpected status %s)."),
    "name_ok": _("Filename accepted. The device is erasing the backup area, please wait ..."),
    "no_data_invite": _("No data invitation received after the filename packet."),
    "device_cancel": _("The device aborted the transfer (double CAN). The most likely reasons are: "
                       "the firmware header was rejected (magic / fw_type / hw_id), or the version is "
                       "lower than the APP currently running on the device (anti-downgrade)."),
    "pkt_retry": _("Packet #%d was not confirmed (%s), retry %d/%d"),
    "pkt_fail": _("Packet #%d failed, the transfer was aborted."),
    "eot1_fail": _("The first EOT was not confirmed (%s)."),
    "eot1_no_invite": _("No invitation received after the first EOT."),
    "eot2_fail": _("The second EOT was not confirmed (%s)."),
    "eot2_no_invite": _("No invitation received after the second EOT."),
    "end_pkt_fail": _("The final empty packet was not confirmed (%s)."),
    "transfer_done": _("All data sent. Waiting for the device to verify and jump to the new APP ..."),
    "cancelled": _("Upgrade cancelled by the user, a double CAN was sent to the device."),
    "write_error": _("Serial write failed: %s"),
    "result_size_crc": _("Device report: size=%d  crc32=0x%08X"),
    "result_ok": _("Device reported: UPDATE OK, jumping to APP."),
    "result_fail": _("Device reported an update failure: %s"),
    "no_result": _("The transfer finished but no final result log was received from the device."),
}

_LOG_LEVEL = {
    "no_invite": "error",
    "name_timeout": "error",
    "name_nak": "error",
    "name_can": "error",
    "name_unknown": "error",
    "no_data_invite": "error",
    "device_cancel": "error",
    "pkt_fail": "error",
    "eot1_fail": "error",
    "eot1_no_invite": "error",
    "eot2_fail": "error",
    "eot2_no_invite": "error",
    "end_pkt_fail": "error",
    "write_error": "error",
    "result_fail": "error",
    "pkt_retry": "warning",
    "cancelled": "warning",
    "no_result": "warning",
    "result_ok": "ok",
}

_DEFAULT_CONFIG = {
    "version": 1,
    "filePath": "",
    "appVersion": "0x0100",
    "fwType": "1",
    "hwId": "1",
    "packet": 1024,
    "timeout": "10",
    "slowMode": False,
    "chunkSize": "256",
    "chunkGap": "10",
    "packetGap": "0",
    "showProto": True,          # 默认把串口收发数据打印到日志区
    "askConfirm": False,        # 默认不再弹模态确认框（信息全部打印到日志区）
}


# ==================== 串口适配器 ====================
class _PortAdapter(object):
    """把 COMTool 插件的异步收发接口适配成同步阻塞的串口风格对象。

    供 bootloader_ymodem.YmodemLink 使用，需要提供：
        timeout / write() / flush() / read() / reset_input_buffer()

    写：PluginItem.sendData 是「入队 -> 独立线程发送 -> 回调」的异步模型，
        因此写完必须等回调确认，并加超时保护（断线时不能死等）。
    读：接收在串口接收线程里通过 onReceived 回调，这里用线程安全队列汇总，
        天然解决 Ymodem 控制字节的粘包与拆包问题。
    """

    def __init__(self, plugin, write_timeout=3.0):
        self.plugin = plugin
        self.timeout = 0.1
        self.write_timeout = write_timeout
        self.rxq = queue.Queue()
        self._buf = bytearray()
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._ok = False
        self._msg = ""
        self._closed = False

    # ---------- 接收线程调用 ----------
    def feed(self, data):
        if self._closed:
            return
        self.rxq.put(bytes(data))

    def close(self):
        self._closed = True
        self._event.set()

    # ---------- 串口风格接口 ----------
    def write(self, data):
        if self._closed:
            raise IOError("port closed")
        if not self.plugin.isConnected():
            raise IOError("serial port is not connected")
        with self._lock:
            self._event.clear()
            self._ok = False
            self._msg = ""
            self.plugin.send(bytes(data), callback=self._on_written)
            if not self._event.wait(self.write_timeout):
                raise IOError("serial write timeout (port closed or device not responding?)")
            if not self._ok:
                raise IOError(self._msg or "serial write failed")

    def _on_written(self, ok, msg, length, path):
        self._ok = bool(ok)
        self._msg = msg or ""
        self._event.set()

    def flush(self):
        pass

    def read(self, n=1):
        """读最多 n 字节（语义与 pyserial 一致：凑够 n 字节或超时才返回）。"""
        if n <= 0:
            n = 1
        deadline = time.monotonic() + (self.timeout if self.timeout and self.timeout > 0 else 0.1)
        while len(self._buf) < n:
            if self._closed:
                break
            try:
                chunk = self.rxq.get_nowait()
            except queue.Empty:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    break
                try:
                    chunk = self.rxq.get(timeout=min(0.02, remain))
                except queue.Empty:
                    continue
            if chunk:
                self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:len(out)]
        return out

    def reset_input_buffer(self):
        try:
            while True:
                self.rxq.get_nowait()
        except queue.Empty:
            pass
        del self._buf[:]


# ==================== 插件 ====================
class Plugin(Plugin_Base):
    '''
        call sequence:
            set vars like hintSignal
            onInit
            onWidget
            onUiInitDone
            onActive
                onConnChanged -> connCallbak   # in UI thread
                send
                onReceived                     # in receive thread
            onDel
    '''
    id = "bootloader"
    name = _("BootLoader Upgrade")

    logSignal = pyqtSignal(str, str)             # level, text
    devTextSignal = pyqtSignal(str)              # 设备日志文本行
    protoSignal = pyqtSignal(int)                # 收到的协议字节
    txSignal = pyqtSignal(object)                # 发出的整帧（bytes，帧级一次）
    monitorSignal = pyqtSignal(object)           # 未升级时串口收到的原始字节（监视模式）
    progressSignal = pyqtSignal(float, str, object)   # fraction, phase code, args
    doneSignal = pyqtSignal(object)              # YmodemResult

    help = (_("Upgrade the APP firmware of a device whose BootLoader supports standard "
              "Ymodem (CRC-16 mode).<br><br>"
              "Steps:<br>"
              "1. Select the serial port and 115200-8N1 on the left, then click OPEN.<br>"
              "2. Choose the raw APP .bin (the plugin adds the 32-byte firmware header) "
              "and fill in the header parameters.<br>"
              "3. Click &quot;Start upgrade&quot;, then press the reset button of the device when "
              "the plugin is waiting for the invitation.<br>"
              "4. The plugin compares the size/CRC32 reported by the device with the local file.<br><br>"
              "Note: downgrade is refused by the device, the new version must not be lower than "
              "the APP version currently running."))

    def __init__(self):
        super().__init__()
        self._port = None
        self._worker = None
        self._running = False
        self._stopEvent = threading.Event()
        self._t0 = 0.0
        self._local = {}
        self._lastProgress = (0.0, 0.0)   # sent, timestamp
        self._parseErrors = []            # 输入解析错误，攒够一次再提示
        # 监视模式：未升级时把串口收到的数据按行显示出来
        self._monBuf = bytearray()
        self._monTimer = None
        # widgets
        self.filePathInput = None
        self.packetCombo = None
        self.timeoutInput = None
        self.slowModeCheck = None
        self.chunkSizeInput = None
        self.chunkGapInput = None
        self.versionInput = None
        self.fwTypeInput = None
        self.hwIdInput = None
        self.startButton = None
        self.statusLabel = None
        self.progressBar = None
        self.progressLabel = None
        self.logArea = None
        self.showProtoCheck = None
        self.askConfirmCheck = None
        self.fwInfoLabel = None
        self.devInfoLabel = None
        self.headerHintLabel = None

    # ---------------- 生命周期 ----------------
    def onInit(self, config):
        super().onInit(config)
        for k in _DEFAULT_CONFIG:
            if k not in self.config:
                self.config[k] = _DEFAULT_CONFIG[k]

    def onWidgetSettings(self, parent):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        # ---- 固件升级参数 ----
        gb = QGroupBox(_("Firmware"))
        grid = QGridLayout()
        gb.setLayout(grid)

        self.filePathInput = QLineEdit(self.config["filePath"])
        self.filePathInput.setToolTip(self.config["filePath"])
        browseButton = QPushButton(_("Browse"))
        browseButton.clicked.connect(self.onBrowseFile)
        grid.addWidget(QLabel(_("File")), 0, 0)
        grid.addWidget(self.filePathInput, 0, 1, 1, 2)
        grid.addWidget(browseButton, 0, 3)

        self.packetCombo = ComboBox()
        self.packetCombo.addItem("1024")
        self.packetCombo.addItem("128")
        self.packetCombo.setCurrentIndex(0 if int(self.config["packet"]) == 1024 else 1)
        self.packetCombo.currentIndexChanged.connect(self.onPacketChanged)
        grid.addWidget(QLabel(_("Packet size")), 1, 0)
        grid.addWidget(self.packetCombo, 1, 1)

        self.timeoutInput = QLineEdit(str(self.config["timeout"]))
        self.timeoutInput.editingFinished.connect(self.onTimeoutChanged)
        grid.addWidget(QLabel(_("Timeout(s)")), 2, 0)
        grid.addWidget(self.timeoutInput, 2, 1)
        grid.addWidget(QLabel(_("Waiting invitation / response")), 2, 2, 1, 2)

        self.slowModeCheck = QCheckBox(_("Slow compatible mode"))
        self.slowModeCheck.setToolTip(_("Split every frame into blocks with a gap between them. "
                                        "Use it only if fast sending fails on your board."))
        self.slowModeCheck.setChecked(bool(self.config["slowMode"]))
        self.slowModeCheck.clicked.connect(self.onSlowModeChanged)
        grid.addWidget(self.slowModeCheck, 3, 0, 1, 4)

        self.chunkSizeInput = QLineEdit(str(self.config["chunkSize"]))
        self.chunkSizeInput.editingFinished.connect(self.onChunkChanged)
        self.chunkGapInput = QLineEdit(str(self.config["chunkGap"]))
        self.chunkGapInput.editingFinished.connect(self.onChunkChanged)
        grid.addWidget(QLabel(_("Block size(B)")), 4, 0)
        grid.addWidget(self.chunkSizeInput, 4, 1)
        grid.addWidget(QLabel(_("Gap(ms)")), 4, 2)
        grid.addWidget(self.chunkGapInput, 4, 3)

        self.askConfirmCheck = QCheckBox(_("Confirm parameters before upgrading"))
        self.askConfirmCheck.setToolTip(_("Show a confirmation dialog listing the firmware header "
                                          "parameters. When off, they are still printed into the log "
                                          "area so you can check them there."))
        self.askConfirmCheck.setChecked(bool(self.config["askConfirm"]))
        self.askConfirmCheck.clicked.connect(self.onAskConfirmChanged)
        grid.addWidget(self.askConfirmCheck, 5, 0, 1, 4)
        layout.addWidget(gb)

        # ---- 固件头参数 ----
        gb2 = QGroupBox(_("Firmware header"))
        grid2 = QGridLayout()
        gb2.setLayout(grid2)

        self.versionInput = QLineEdit(str(self.config["appVersion"]))
        self.versionInput.setPlaceholderText("0x0101")
        self.versionInput.setToolTip(_("Accepted formats: 0x0101 / 0101 / 257.") + "\n"
                                     + _("It is written into the firmware header, and the device uses "
                                         "it to refuse downgrade."))
        self.versionInput.editingFinished.connect(self.onHeaderChanged)
        self.versionInput.textChanged.connect(self.onHeaderTextChanged)
        grid2.addWidget(QLabel(_("APP version")), 0, 0)
        grid2.addWidget(self.versionInput, 0, 1)

        self.fwTypeInput = QLineEdit(str(self.config["fwType"]))
        self.fwTypeInput.setPlaceholderText("1")
        self.fwTypeInput.setToolTip(_("Accepted formats: 0x10 / 010 / 16.") + "\n"
                                    + _("Must match FW_TYPE_APP in the device boot_config.h (1 by default)."))
        self.fwTypeInput.editingFinished.connect(self.onHeaderChanged)
        self.fwTypeInput.textChanged.connect(self.onHeaderTextChanged)
        grid2.addWidget(QLabel(_("fw_type")), 1, 0)
        grid2.addWidget(self.fwTypeInput, 1, 1)

        self.hwIdInput = QLineEdit(str(self.config["hwId"]))
        self.hwIdInput.setPlaceholderText("1")
        self.hwIdInput.setToolTip(_("Accepted formats: 0x10 / 010 / 16.") + "\n"
                                  + _("Must match FW_HW_ID in the device boot_config.h (1 by default)."))
        self.hwIdInput.editingFinished.connect(self.onHeaderChanged)
        self.hwIdInput.textChanged.connect(self.onHeaderTextChanged)
        grid2.addWidget(QLabel(_("hw_id")), 2, 0)
        grid2.addWidget(self.hwIdInput, 2, 1)

        magicLabel = QLabel("0x%08X" % ymo.FW_MAGIC)
        magicLabel.setToolTip(_("Firmware magic, fixed, defined by the device bootloader"))
        grid2.addWidget(QLabel(_("magic")), 3, 0)
        grid2.addWidget(magicLabel, 3, 1)

        hint = QLabel(_("fw_type / hw_id must match the device bootloader, otherwise the device "
                        "rejects the firmware and erases the backup area in vain."))
        hint.setWordWrap(True)
        grid2.addWidget(hint, 4, 0, 1, 2)

        # 实时解析结果（只读提示，不修改输入框内容）
        self.headerHintLabel = QLabel("")
        self.headerHintLabel.setWordWrap(True)
        grid2.addWidget(self.headerHintLabel, 5, 0, 1, 2)
        layout.addWidget(gb2)

        layout.addStretch()
        return widget

    def onWidgetMain(self, parent):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        # ---- 状态与进度 ----
        self.statusLabel = QLabel(_("Ready"))
        self.statusLabel.setProperty("class", "bootStatus")
        layout.addWidget(self.statusLabel)

        progressLayout = QHBoxLayout()
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 1000)
        self.progressBar.setValue(0)
        self.progressBar.setTextVisible(False)
        progressLayout.addWidget(self.progressBar, 1)
        self.progressLabel = QLabel("0.0%")
        self.progressLabel.setMinimumWidth(170)
        progressLayout.addWidget(self.progressLabel)
        layout.addLayout(progressLayout)

        # ---- 按钮 ----
        buttonLayout = QHBoxLayout()
        self.startButton = QPushButton(_("Start upgrade"))
        self.startButton.clicked.connect(self.onStartClicked)
        buttonLayout.addWidget(self.startButton)
        self.showProtoCheck = QCheckBox(_("Show serial TX/RX data"))
        self.showProtoCheck.setToolTip(_("Print every frame sent to and every protocol byte received "
                                         "from the device into the log area."))
        self.showProtoCheck.setChecked(bool(self.config["showProto"]))
        self.showProtoCheck.clicked.connect(self.onShowProtoChanged)
        buttonLayout.addWidget(self.showProtoCheck)
        buttonLayout.addStretch()
        clearButton = QPushButton(_("Clear log"))
        clearButton.clicked.connect(lambda: self.logArea and self.logArea.clear())
        buttonLayout.addWidget(clearButton)
        layout.addLayout(buttonLayout)

        # ---- 日志 ----
        self.logArea = QPlainTextEdit()
        self.logArea.setReadOnly(True)
        self.logArea.setMaximumBlockCount(5000)
        self.logArea.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.logArea, 1)

        # 监视模式的空闲刷出定时器：设备只发 'C' 之类的短数据没有换行时，
        # 200ms 内没有新数据就先把已经收到的部分刷出来，避免"看着像没收到"。
        self._monTimer = QTimer(self)
        self._monTimer.setSingleShot(True)
        self._monTimer.setInterval(200)
        self._monTimer.timeout.connect(self.onMonitorFlush)
        return widget

    def onWidgetFunctional(self, parent):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        gb = QGroupBox(_("Firmware"))
        gbLayout = QVBoxLayout()
        gb.setLayout(gbLayout)
        self.fwInfoLabel = QLabel("-")
        self.fwInfoLabel.setWordWrap(True)
        self.fwInfoLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        gbLayout.addWidget(self.fwInfoLabel)
        layout.addWidget(gb)

        gb2 = QGroupBox(_("Device report"))
        gb2Layout = QVBoxLayout()
        gb2.setLayout(gb2Layout)
        self.devInfoLabel = QLabel("-")
        self.devInfoLabel.setWordWrap(True)
        self.devInfoLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        gb2Layout.addWidget(self.devInfoLabel)
        exportButton = QPushButton(_("Export log"))
        exportButton.clicked.connect(self.onExportLog)
        gb2Layout.addWidget(exportButton)
        layout.addWidget(gb2)

        layout.addStretch()
        return widget

    def onWidgetStatusBar(self, parent):
        self.statusBar = statusBar(rxTxCount=False)
        return self.statusBar

    def onUiInitDone(self):
        # 信号 -> UI（全部在主线程执行）
        self.logSignal.connect(self.onLog)
        self.devTextSignal.connect(self.onDeviceText)
        self.protoSignal.connect(self.onProto)
        self.txSignal.connect(self.onTxFrame)
        self.monitorSignal.connect(self.onMonitorData)
        self.progressSignal.connect(self.onProgress)
        self.doneSignal.connect(self.onDone)
        # 启动时只做静默归一化：历史配置里的写法差异不该弹错误框
        self.onHeaderChanged(silent=True)
        self.onTimeoutChanged(silent=True)
        self.onChunkChanged(silent=True)
        self._parseErrors = []
        self.updateHeaderHint()
        self.onFileChanged()
        self.onLog("info", _("Plugin ready. Select the serial port, open it, then choose a firmware file."))

    def onDel(self):
        self._stopEvent.set()
        self._resetMonitor()
        if self._port is not None:
            self._port.close()
        if self._worker is not None and self._worker.is_alive():
            self._worker.join(timeout=3.0)
        self._worker = None

    # ---------------- 连接回调 ----------------
    def onConnChanged(self, status, msg):
        super().onConnChanged(status, msg)
        if status == ConnectionStatus.CONNECTED:
            self._resetMonitor()
            self.onLog("info", _("Connected."))
            self.onLog("info", _("Monitoring serial data. Received bytes will be shown below."))
        elif status == ConnectionStatus.CLOSED:
            self._resetMonitor()
            self.onLog("info", _("Closed."))
        elif status == ConnectionStatus.LOSE:
            self.onLog("warning", _("Connection lost."))
        if self._running and status != ConnectionStatus.CONNECTED:
            self._stopEvent.set()
            self.onLog("warning", _("The connection is down, aborting the upgrade."))

    # ---------------- 接收（串口接收线程，禁止操作控件） ----------------
    def onReceived(self, data):
        port = self._port
        if port is not None:
            # 升级进行中：交给 Ymodem 协议层解析
            port.feed(data)
            return
        # 空闲（未升级）：进入监视模式，原样显示收到的数据
        self.monitorSignal.emit(bytes(data))

    # ---------------- 监视模式（打开串口后一直显示收到的数据） ----------------
    def onMonitorData(self, data):
        """把串口收到的字节按行整理后写入日志区（UI 线程）。"""
        if self._running or data is None:
            return
        self._monBuf.extend(data)
        self._flushMonitor(partial=False)
        if len(self._monBuf) > 1024:      # 防御：长时间无换行的数据也别无限攒着
            self._flushMonitor(partial=True)
        if self._monTimer is not None:
            self._monTimer.start()

    def onMonitorFlush(self):
        """空闲 200ms：把还没换行的残留数据先刷出来。"""
        if not self._running:
            self._flushMonitor(partial=True)

    def _flushMonitor(self, partial):
        while True:
            idx = self._monBuf.find(b"\n")
            if idx < 0:
                break
            raw = bytes(self._monBuf[:idx])
            del self._monBuf[:idx + 1]
            line = _fmt_monitor_line(raw)
            if line.strip():
                self._appendLog("[MON] %s" % line)
        if partial and self._monBuf:
            line = _fmt_monitor_line(bytes(self._monBuf))
            del self._monBuf[:]
            if line.strip():
                self._appendLog("[MON] %s" % line)

    def _resetMonitor(self):
        del self._monBuf[:]
        if self._monTimer is not None:
            self._monTimer.stop()

    # ---------------- 参数输入 ----------------
    def onBrowseFile(self):
        oldPath = self.filePathInput.text() or os.getcwd()
        path, _ft = QFileDialog.getOpenFileName(self.filePathInput, _("Select firmware file"),
                                                oldPath, _("Binary file (*.bin);;All Files (*)"))
        if not path:
            return
        self.filePathInput.setText(path)
        self.filePathInput.setToolTip(path)
        self.config["filePath"] = path
        self.onFileChanged()

    def onFileChanged(self):
        path = self.filePathInput.text().strip()
        if not path or not os.path.isfile(path):
            self.fwInfoLabel.setText("-")
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            self.fwInfoLabel.setText(_("Read file failed:") + " " + str(e))
            return
        warn = ""
        if ymo.looks_like_fw_header(data):
            warn = "\n" + _("Warning: this file already starts with a firmware magic, "
                            "it may already contain the header; do NOT select a header-prepended file.")
        self._local["app_size"] = len(data)
        self._local["app_crc"] = zlib_crc32(data)
        self.fwInfoLabel.setText(
            "%s: %d B\n%s: %d B\n%s: 0x%08X\n%s: %s%s" % (
                _("Raw bin"), len(data),
                _("Upgrade package"), len(data) + ymo.FW_HEADER_SIZE,
                _("Local CRC32"), self._local["app_crc"],
                _("Max allowed"), "%d B" % ymo.APP_MAX_SIZE,
                warn))

    def onPacketChanged(self):
        self.config["packet"] = 128 if self.packetCombo.currentText() == "128" else 1024

    def onTimeoutChanged(self, silent=False):
        v = self._parseInt(self.timeoutInput, 10.0, lo=0.5, hi=3600.0,
                           isFloat=True, silent=silent)
        self.config["timeout"] = str(v)
        if not silent:
            self._flushParseErrors()

    def onSlowModeChanged(self):
        self.config["slowMode"] = self.slowModeCheck.isChecked()

    def onChunkChanged(self, silent=False):
        size = self._parseInt(self.chunkSizeInput, 256, lo=16, hi=1024, silent=silent)
        gap = self._parseInt(self.chunkGapInput, 10.0, lo=0.0, hi=1000.0,
                            isFloat=True, silent=silent)
        self.config["chunkSize"] = str(size)
        self.config["chunkGap"] = str(gap)
        if not silent:
            self._flushParseErrors()

    def onShowProtoChanged(self):
        self.config["showProto"] = self.showProtoCheck.isChecked()

    def onAskConfirmChanged(self):
        self.config["askConfirm"] = self.askConfirmCheck.isChecked()

    def onHeaderTextChanged(self, *args):
        """输入框内容变化时实时刷新解析提示（不修改输入框自身内容）。"""
        self.updateHeaderHint()

    def updateHeaderHint(self):
        """把三个固件头字段的解析结果显示出来：合法显示归一化数值，非法标红。"""
        if self.headerHintLabel is None:
            return
        parts, bad = [], []
        for name, lineEdit in ((_("APP version"), self.versionInput),
                               (_("fw_type"), self.fwTypeInput),
                               (_("hw_id"), self.hwIdInput)):
            ok, value = self._tryParse(lineEdit.text(), allowHex=True)
            if not ok:
                bad.append(name)
            elif value is not None:
                parts.append("%s=%s" % (name, _fmt_hex_dec(value)))
        if bad:
            self.headerHintLabel.setStyleSheet("color:#f44336;")
            self.headerHintLabel.setText(_("Invalid format:") + " " + ", ".join(bad))
        else:
            self.headerHintLabel.setStyleSheet("")
            self.headerHintLabel.setText((_("Parsed:") + " " + "   ".join(parts)) if parts else "")

    def onHeaderChanged(self, silent=False):
        version = self._parseInt(self.versionInput, 0x0100, lo=0, hi=0xFFFFFFFF,
                                 allowHex=True, silent=silent)
        fwType = self._parseInt(self.fwTypeInput, 1, lo=0, hi=0xFFFFFFFF,
                                allowHex=True, silent=silent)
        hwId = self._parseInt(self.hwIdInput, 1, lo=0, hi=0xFFFFFFFF,
                              allowHex=True, silent=silent)
        # 归一化成可读且可回填的十六进制字面量（<=0xFFFF 用 4 位，便于与 boot_config.h 对照）
        self.config["appVersion"] = ("0x%04X" % version) if version <= 0xFFFF else ("0x%X" % version)
        self.config["fwType"] = str(fwType)
        self.config["hwId"] = str(hwId)
        self.versionInput.setText(self.config["appVersion"])
        if not silent:
            self._flushParseErrors()

    @classmethod
    def _tryParse(cls, text, allowHex=False, isFloat=False, lo=0, hi=0xFFFFFFFF):
        """纯解析数值，不触碰任何控件。返回 (ok, value)。

        空串视为合法但无值 -> (True, None)，由调用方决定用默认值。
        allowHex=True 时支持 "0x0101"、"0101"（前导零按十六进制）与含 a~f 的字面量；
        其余按十进制解析。

        注意：int(x, 16) 不接受 "0x" 前缀（前缀只在 base=0 时才合法），因此必须先剥掉
        前缀再按 16 进制解析，否则所有 0x 写法都会解析失败。
        """
        text = (text or "").strip()
        if not text:
            return (True, None)
        value = None
        if isFloat:
            try:
                value = float(text)
            except ValueError:
                value = None
        elif allowHex:
            low = text.lower()
            try:
                if low.startswith("0x"):
                    body = low[2:]
                    if not body:
                        raise ValueError(text)
                    value = int(body, 16)
                elif any(c in "abcdef" for c in low):
                    value = int(low, 16)
                elif len(low) > 1 and low[0] == "0":
                    value = int(low, 16)      # 前导零按十六进制（0x 的常见省略写法）
                else:
                    value = int(low, 10)
            except ValueError:
                value = None
        else:
            try:
                value = int(text, 10)
            except ValueError:
                value = None
        if value is None:
            return (False, None)
        if value < lo:
            value = lo
        if value > hi:
            value = hi
        return (True, value)

    def _parseInt(self, lineEdit, default, lo=0, hi=0xFFFFFFFF, isFloat=False,
                  allowHex=False, silent=False):
        """解析输入框并回填归一化后的文本；非法时回退 default。

        错误信息先入队，由 _flushParseErrors 统一合并成一次提示。
        """
        raw = (lineEdit.text() or "").strip()
        ok, value = self._tryParse(raw, allowHex=allowHex, isFloat=isFloat, lo=lo, hi=hi)
        if not ok:
            if not silent:
                self._parseErrors.append(_("Invalid value:") + " " + raw + " -> " + str(default))
            value = default
        elif value is None:
            value = default
        lineEdit.setText(("%g" % value) if isFloat else str(value))
        return value

    def _flushParseErrors(self):
        """把本轮累积的输入错误合并成一次提示，避免连弹多个对话框。"""
        if not self._parseErrors:
            return False
        msgs = self._parseErrors
        self._parseErrors = []
        self.hintSignal.emit("error", _("Error"), "\n".join(msgs))
        return True

    # ---------------- 开始 / 取消 ----------------
    def onStartClicked(self):
        """点击「开始升级」。每一条提前返回的路径都会写日志，避免出现"点了没反应"。"""
        if self._running:
            self.onCancelClicked()
            return
        self.onLog("info", "-" * 40)
        self.onLog("info", _("Start button clicked, checking parameters ..."))

        if not self.isConnected():
            self.onLog("error", _("Not connected, please open the serial port first."))
            self.hintSignal.emit("warning", _("Warning"), _("Connect first please"))
            return

        path = self.filePathInput.text().strip()
        if not path or not os.path.isfile(path):
            self.onLog("error", _("Firmware file not found:") + " " + (path or "(empty)"))
            self.hintSignal.emit("error", _("Error"), _("Please select a valid firmware file (.bin)."))
            return
        try:
            with open(path, "rb") as f:
                appBin = f.read()
        except Exception as e:
            self.onLog("error", _("Read file failed:") + " " + str(e))
            self.hintSignal.emit("error", _("Error"), _("Read file failed:") + " " + str(e))
            return
        if len(appBin) == 0:
            self.onLog("error", _("The firmware file is empty."))
            self.hintSignal.emit("error", _("Error"), _("The firmware file is empty."))
            return
        if len(appBin) > ymo.APP_MAX_SIZE:
            msg = _("Firmware is too large: %d B, the device accepts at most %d B.") \
                % (len(appBin), ymo.APP_MAX_SIZE)
            self.onLog("error", msg)
            self.hintSignal.emit("error", _("Error"), msg)
            return
        self.onLog("info", "%s %s (%d B)" % (_("Firmware file:"), path, len(appBin)))

        if ymo.looks_like_fw_header(appBin):
            self.onLog("warning", _("Warning: this file already starts with a firmware magic, "
                                    "it may already contain the header; do NOT select a "
                                    "header-prepended file."))
            answer = QMessageBox.question(
                self.mainWidget, _("Warning"),
                _("This file already starts with a firmware magic (it may already contain the "
                  "32-byte header). Continuing will add another header and the device will reject "
                  "it.\n\nContinue anyway?"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                self.onLog("warning", _("Cancelled: the file may already contain a firmware header."))
                return

        params = {
            "file": path,
            "appBin": appBin,
            "version": self._parseInt(self.versionInput, 0x0100, lo=0, hi=0xFFFFFFFF, allowHex=True),
            "fwType": self._parseInt(self.fwTypeInput, 1, lo=0, hi=0xFFFFFFFF, allowHex=True),
            "hwId": self._parseInt(self.hwIdInput, 1, lo=0, hi=0xFFFFFFFF, allowHex=True),
            "packet": 128 if self.packetCombo.currentText() == "128" else 1024,
            "timeout": self._parseInt(self.timeoutInput, 10.0, lo=0.5, hi=3600.0, isFloat=True),
            "slowMode": self.slowModeCheck.isChecked(),
            "chunkSize": self._parseInt(self.chunkSizeInput, 256, lo=16, hi=1024),
            "chunkGap": self._parseInt(self.chunkGapInput, 10.0, lo=0.0, hi=1000.0, isFloat=True),
            "packetGap": self._parseFloatSafe(self.config.get("packetGap", "0")),
        }
        # 任一参数填写非法时回退值已生效，但必须让用户先确认，避免拿错误参数去升级
        if self._flushParseErrors():
            self.onLog("error", _("Parameter format error, upgrade cancelled. Please fix it."))
            return
        # 把固件头字段回填成归一化写法，避免点一次开始后版本框被改写成十进制
        self.onHeaderChanged(silent=True)
        params["crc"] = zlib_crc32(appBin)

        self.onLog("info", _("Upgrade parameters:"))
        for line in self.paramsText(params).splitlines():
            self.onLog("info", "  " + line)

        if self.config.get("askConfirm", False):
            self.onLog("info", _("Waiting for your confirmation in the dialog ..."))
            if not self.onConfirm(params):
                self.onLog("warning", _("Cancelled in the confirmation dialog."))
                return
        self._local["app_size"] = len(appBin)
        self._local["app_crc"] = params["crc"]
        self._begin(params)

    def paramsText(self, params):
        """把本次升级的全部参数整理成多行文本（日志与确认框共用）。"""
        header = ymo.parse_fw_header(ymo.build_fw_header(
            params["version"], len(params["appBin"]),
            fw_type=params["fwType"], hw_id=params["hwId"]))
        lines = [
            "%s: %s" % (_("File"), os.path.basename(params["file"])),
            "%s: %d B" % (_("Raw bin"), len(params["appBin"])),
            "%s: %d B" % (_("Upgrade package"), len(params["appBin"]) + ymo.FW_HEADER_SIZE),
            "%s: 0x%08X" % (_("Local CRC32"), params["crc"]),
            "%s: 0x%08X" % (_("magic"), header["magic"]),
            "%s: %d" % (_("fw_type"), header["fw_type"]),
            "%s: %d" % (_("hw_id"), header["hw_id"]),
            "%s: 0x%04X" % (_("APP version"), header["version"]),
            "%s: %d" % (_("Packet size"), params["packet"]),
            "%s: %g s" % (_("Timeout(s)"), params["timeout"]),
        ]
        if params["slowMode"]:
            lines.append("%s: %d B / %g ms" % (_("Slow compatible mode"),
                                               params["chunkSize"], params["chunkGap"]))
        return "\n".join(lines)

    def _parseFloatSafe(self, text):
        try:
            return float(text)
        except (TypeError, ValueError):
            return 0.0

    def onCancelClicked(self):
        if not self._running:
            return
        self._stopEvent.set()
        self.startButton.setEnabled(False)
        self.onLog("warning", _("Cancelling, waiting for the current step to finish safely ..."))

    def onConfirm(self, params):
        """升级前确认固件头参数（hw_id 填错会导致设备白擦一次备份区）。

        参数同时已写入日志区，因此即使这个模态框被误关，日志里也能查到本次的参数。
        """
        box = QMessageBox(self.mainWidget.window() if self.mainWidget is not None else None)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle(_("Confirm upgrade"))
        box.setText(_("Please confirm the firmware header parameters before upgrading:"))
        box.setInformativeText(self.paramsText(params))
        box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        box.setDefaultButton(QMessageBox.Cancel)
        checkBox = QCheckBox(_("Do not ask again"))
        box.setCheckBox(checkBox)
        box.raise_()
        box.activateWindow()
        ret = box.exec_()
        if checkBox.isChecked():
            self.config["askConfirm"] = False
            if self.askConfirmCheck is not None:
                self.askConfirmCheck.setChecked(False)
        return ret == QMessageBox.Ok

    def _begin(self, params):
        # 进入升级流程：停止监视模式，之后的收发由 Ymodem 协议层负责显示
        self._resetMonitor()
        self._running = True
        self._stopEvent = threading.Event()
        self._t0 = time.monotonic()
        self._lastProgress = (0.0, self._t0)
        self._port = _PortAdapter(self)
        self.progressBar.setValue(0)
        self.progressLabel.setText("0.0%")
        self._setStatus(_("Starting ..."), "busy")
        self.startButton.setText(_("Cancel"))
        self.startButton.setEnabled(True)
        self.onLog("info", "-" * 40)
        self.onLog("info", _("Start upgrade:") + " " + os.path.basename(params["file"]))
        self.onLog("info", "magic=0x%08X fw_type=%d hw_id=%d version=0x%04X packet=%d"
                   % (ymo.FW_MAGIC, params["fwType"], params["hwId"],
                      params["version"], params["packet"]))
        self._worker = threading.Thread(target=self._workerFunc, args=(params,))
        self._worker.setDaemon(True)
        self._worker.start()

    def _workerFunc(self, params):
        """工作线程：加固件头 -> Ymodem 发送 -> 结束。所有 UI 交互都通过信号。"""
        try:
            header = ymo.build_fw_header(params["version"], len(params["appBin"]),
                                         fw_type=params["fwType"], hw_id=params["hwId"])
            package = header + params["appBin"]
            link = ymo.YmodemLink(self._port,
                                  on_text=lambda t: self.devTextSignal.emit(t),
                                  on_proto=lambda b: self.protoSignal.emit(b),
                                  on_write=lambda d: self.txSignal.emit(bytes(d)),
                                  log=lambda code, *a: self.logSignal.emit(
                                      _LOG_LEVEL.get(code, "info"), _log_text(code, a)),
                                  stop_check=self._stopEvent.is_set)
            if params["slowMode"]:
                link.chunk_size = int(params["chunkSize"])
                link.chunk_gap = float(params["chunkGap"]) / 1000.0
            result = ymo.ymodem_send(
                link, package, os.path.basename(params["file"]),
                packet=params["packet"],
                timeout=params["timeout"],
                packet_gap=float(params["packetGap"]) / 1000.0,
                on_progress=lambda f, lab, *a: self.progressSignal.emit(f, lab, a))
        except Exception as e:
            result = ymo.YmodemResult()
            result.reason = "write_error"
            result.detail = str(e)
            self.logSignal.emit("error", _log_text("write_error", (str(e),)))
        port = self._port
        if port is not None:
            port.close()
        self.doneSignal.emit(result)

    # ---------------- 信号处理（主线程） ----------------
    def onLog(self, level, text):
        if level == "error":
            prefix = "!!"
        elif level == "warning":
            prefix = " *"
        elif level == "ok":
            prefix = " +"
        else:
            prefix = "  "
        self._appendLog("%s %s" % (prefix, text))

    def onDeviceText(self, text):
        self._appendLog("[DEV] %s" % text)

    def onProto(self, value):
        if self.showProtoCheck is not None and self.showProtoCheck.isChecked():
            self._appendLog("[RX] 0x%02X %s" % (value, ymo.proto_name(value)))

    def onTxFrame(self, data):
        """把发往设备的每一帧打印出来（分块发送也只记一次，避免刷屏）。"""
        if self.showProtoCheck is None or not self.showProtoCheck.isChecked():
            return
        data = bytes(data)
        if len(data) == 1:
            self._appendLog("[TX] %s" % ymo.proto_name(data[0]))
        elif data and data[0] in (ymo.SOH, ymo.STX):
            datalen = ymo.YMO_PKT_128 if data[0] == ymo.SOH else ymo.YMO_PKT_1024
            self._appendLog("[TX] seq=%d %s %dB (frame %dB)"
                            % (data[1], ymo.proto_name(data[0]), datalen, len(data)))
        else:
            head = " ".join("%02X" % b for b in data[:16])
            self._appendLog("[TX] %dB  %s%s" % (len(data), head, " ..." if len(data) > 16 else ""))

    def onProgress(self, fraction, label, args):
        self.progressBar.setValue(int(max(0.0, min(1.0, fraction)) * 1000))
        text = "%.1f%%" % (fraction * 100.0)
        if args and len(args) >= 2:
            sent, total = int(args[0]), int(args[1])
            now = time.monotonic()
            lastSent, lastT = self._lastProgress
            dt = now - lastT
            if dt >= 0.5:
                speed = (sent - lastSent) / dt if dt > 0 else 0.0
                self._lastProgress = (sent, now)
                self._speed = speed
                self._eta = (total - sent) / speed if speed > 0 else 0.0
            speed = getattr(self, "_speed", 0.0)
            eta = getattr(self, "_eta", 0.0)
            text += "  %s/s  %s %s" % (_format_bytes(speed), _("ETA"), _format_time(eta))
        self.progressLabel.setText(text)
        phase = _PHASE_MSG.get(label)
        if phase:
            self._setStatus(phase, "busy")

    def onDone(self, result):
        self._running = False
        self._resetMonitor()
        self.startButton.setText(_("Start upgrade"))
        self.startButton.setEnabled(True)
        if self._port is not None:
            self._port.close()
            self._port = None

        ok = self._conclude(result)
        if result.reason == "cancelled":
            self._setStatus(_("Upgrade cancelled."), "warning")
            self.onLog("warning", _("Upgrade cancelled."))
        elif ok is True:
            self.progressBar.setValue(1000)
            self.progressLabel.setText("100.0%")
            self._setStatus(_("Upgrade succeeded."), "ok")
            self.onLog("ok", _("Upgrade succeeded."))
        elif ok is False:
            self._setStatus(_("Upgrade failed."), "error")
            self.onLog("error", _("Upgrade failed."))
        else:
            self._setStatus(_("Transfer finished, result unknown."), "warning")
            self.onLog("warning", _("Transfer finished, result unknown."))

    def _conclude(self, result):
        """结合主机结果与设备回报给出结论，并更新右栏。返回 True/False/None。"""
        lines = []
        devSize = result.device_size
        devCrc = result.device_crc
        localSize = self._local.get("app_size")
        localCrc = self._local.get("app_crc")

        if devSize is None:
            lines.append("%s: -" % _("size"))
        else:
            mark = "" if localSize is None else ("  [OK]" if devSize == localSize else "  [MISMATCH]")
            lines.append("%s: %d%s" % (_("size"), devSize, mark))
        if devCrc is None:
            lines.append("%s: -" % _("crc32"))
        else:
            mark = "" if localCrc is None else ("  [OK]" if devCrc == localCrc else "  [MISMATCH]")
            lines.append("%s: 0x%08X%s" % (_("crc32"), devCrc, mark))
        if result.update_msg:
            lines.append("%s: %s" % (_("Result"), result.update_msg))
        elif result.update_ok is True:
            lines.append("%s: %s" % (_("Result"), _("UPDATE OK")))
        else:
            lines.append("%s: %s" % (_("Result"), _("unknown")))
        lines.append("%s: %s" % (_("Local"), "app=%s B crc=0x%08X"
                                 % (localSize, localCrc if localCrc is not None else 0)))
        if result.elapsed:
            lines.append("%s: %.1f s   %s: %d"
                         % (_("Elapsed"), result.elapsed, _("Retries"), result.retries))
        self.devInfoLabel.setText("\n".join(lines))

        if not result.ok:
            if result.reason == "device_cancel" and result.fail_seq <= 1:
                self.onLog("error", _("The device rejected the firmware header at the first packet. "
                                      "Check fw_type/hw_id/version (anti-downgrade) and make sure the "
                                      "device uses the same bootloader configuration."))
            return False

        # 传输成功：再看设备结论与 CRC 对拍
        if result.update_ok is False:
            self.onLog("error", _("The device received all data but failed to apply it: %s")
                       % result.update_msg)
            return False
        if devCrc is not None and localCrc is not None and devCrc != localCrc:
            self.onLog("error", _("CRC32 mismatch: device=0x%08X local=0x%08X")
                       % (devCrc, localCrc))
            return False
        if devSize is not None and localSize is not None and devSize != localSize:
            self.onLog("error", _("Size mismatch: device=%d local=%d") % (devSize, localSize))
            return False
        if result.update_ok is None:
            return None
        return True

    # ---------------- 杂项 ----------------
    def _appendLog(self, text):
        if self.logArea is None:
            return
        self.logArea.appendPlainText("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), text))
        self.logArea.moveCursor(QTextCursor.End)

    def _setStatus(self, text, level="info"):
        if self.statusLabel is None:
            return
        self.statusLabel.setText(text)
        self.statusLabel.setProperty("bootLevel", level)
        self.statusLabel.style().unpolish(self.statusLabel)
        self.statusLabel.style().polish(self.statusLabel)
        self.statusLabel.update()
        if self.statusBar is not None:
            self.statusBar.setMsg("info" if level == "busy" else level, text)

    def onExportLog(self):
        if self.logArea is None or self.logArea.toPlainText() == "":
            self.hintSignal.emit("warning", _("Warning"), _("Nothing to export."))
            return
        default = os.path.join(os.getcwd(),
                               "bootloader_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"))
        path, _ft = QFileDialog.getSaveFileName(self.mainWidget, _("Select file"), default,
                                                _("Log file (*.log);;All Files (*)"))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.logArea.toPlainText())
            self.onLog("info", _("Log saved to:") + " " + path)
        except Exception as e:
            self.hintSignal.emit("error", _("Error"), _("Save file failed:") + " " + str(e))


# ==================== 工具函数 ====================
_PHASE_MSG = {
    "wait_invite": _("Waiting for device invitation ..."),
    "name": _("Sending filename packet ..."),
    "name_ok": _("Device is erasing the backup area ..."),
    "progress": _("Transferring ..."),
    "verify": _("Verifying, waiting for device result ..."),
    "done": _("Done"),
}


def zlib_crc32(data):
    """标准 CRC32（与设备端 crc32_calc / zlib 一致）。"""
    return zlib.crc32(data) & 0xFFFFFFFF


def _log_text(code, args):
    template = _LOG_MSG.get(code)
    if template is None:
        template = code
    if not args:
        return template
    try:
        return template % args
    except Exception:
        return "%s %r" % (template, args)


_MONITOR_LINE_MAX = 200


def _fmt_monitor_line(raw):
    """把监视模式下收到的一行原始字节渲染成可读文本。

    - 按 UTF-8 解码（失败用替换符），保证中文日志正常显示；
    - 丢弃 '\\r'（否则日志行会被回车覆盖），保留 '\\t'；
    - 其余不可打印控制字符（如 ACK 0x06）转成 <06> 形式，便于判断确实有数据到达；
    - 超长行截断（设备强制升级时会持续发 'C'，不截断会产生上千字符的日志行）。
    """
    text = bytes(raw).decode("utf-8", errors="replace")
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\r":
            continue
        if ch == "\n" or ch == "\t" or 0x20 <= o < 0x7F or o >= 0xA0:
            out.append(ch)
        else:
            out.append("<%02X>" % o)
    line = "".join(out)
    if len(line) > _MONITOR_LINE_MAX:
        line = line[:_MONITOR_LINE_MAX] + " ... (%d chars)" % len(line)
    return line


def _fmt_hex_dec(value):
    """把整数格式化成 0x%X；大于 9 时附上十进制，便于与十进制输入互相核对。"""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return str(value)
    return ("0x%X (%d)" % (v, v)) if v > 9 else ("0x%X" % v)


def _format_bytes(value):
    """把 '字节/秒' 格式化成易读字符串。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "-"
    if v < 1024:
        return "%d B" % int(v)
    if v < 1024 * 1024:
        return "%.1f KB" % (v / 1024.0)
    return "%.1f MB" % (v / 1048576.0)


def _format_time(seconds):
    try:
        s = int(max(0, seconds))
    except (TypeError, ValueError):
        return "--:--"
    return "%02d:%02d" % (s // 60, s % 60)
