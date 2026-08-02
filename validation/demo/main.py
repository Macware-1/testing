#!/usr/bin/env python3
"""CAN-ETH Gateway Demo Application.

A PyQt5 tabbed GUI demonstrating all gateway capabilities:
  - Connection / device status
  - CAN TX and RX
  - J1939 TX and RX
  - Device configuration

Run from the validation/ directory:
    python demo/main.py
"""

import sys
import os
import time
import threading
from typing import Optional

# Ensure the sdk package is importable when running from validation/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QGroupBox, QFormLayout, QComboBox, QSpinBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QStatusBar, QMessageBox,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor

from sdk import GatewayClient
from sdk.protocols.clog import CLOGFrame, CLOGType
from sdk.protocols.status import StatusFrame
from sdk.protocols.j1939 import J1939Frame, WELL_KNOWN_PGNS


# ── Signals helper (cross-thread Qt signal emission) ─────────────────────────

class _Signals(QObject):
    clog_frame   = pyqtSignal(object)
    status_frame = pyqtSignal(object)
    log_message  = pyqtSignal(str)


signals = _Signals()


# ══════════════════════════════════════════════════════════════════════════════
#  Connection / Status Tab
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Connection group
        conn_box = QGroupBox("Connection")
        form = QFormLayout(conn_box)
        self._ip_edit = QLineEdit("192.168.1.100")
        self._connect_btn = QPushButton("Connect")
        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.setEnabled(False)
        form.addRow("Gateway IP:", self._ip_edit)
        btn_row = QHBoxLayout()
        btn_row.addWidget(self._connect_btn)
        btn_row.addWidget(self._disconnect_btn)
        form.addRow("", btn_row)
        layout.addWidget(conn_box)

        # Device status group
        status_box = QGroupBox("Device Status")
        status_form = QFormLayout(status_box)
        self._lbl_ip       = QLabel("—")
        self._lbl_uptime   = QLabel("—")
        self._lbl_heap     = QLabel("—")
        self._lbl_tasks    = QLabel("—")
        self._lbl_fw       = QLabel("—")
        status_form.addRow("Gateway IP:",   self._lbl_ip)
        status_form.addRow("Uptime:",       self._lbl_uptime)
        status_form.addRow("Free heap:",    self._lbl_heap)
        status_form.addRow("FreeRTOS tasks:", self._lbl_tasks)
        status_form.addRow("Firmware:",     self._lbl_fw)
        layout.addWidget(status_box)

        # Log
        log_box = QGroupBox("Log")
        log_layout = QVBoxLayout(log_box)
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setFont(QFont("Monospace", 9))
        log_layout.addWidget(self._log)
        layout.addWidget(log_box)

        self._connect_btn.clicked.connect(self._on_connect)
        self._disconnect_btn.clicked.connect(self._on_disconnect)
        signals.status_frame.connect(self._on_status)
        signals.log_message.connect(self._append_log)

    def _on_connect(self):
        ip = self._ip_edit.text().strip()
        if not ip:
            return
        self._connect_btn.setEnabled(False)
        self._app.connect(ip)
        self._disconnect_btn.setEnabled(True)

    def _on_disconnect(self):
        self._app.disconnect()
        self._connect_btn.setEnabled(True)
        self._disconnect_btn.setEnabled(False)
        self._lbl_ip.setText("—")
        self._lbl_uptime.setText("—")
        self._lbl_heap.setText("—")
        self._lbl_tasks.setText("—")
        self._lbl_fw.setText("—")

    def _on_status(self, f: StatusFrame):
        self._lbl_ip.setText(f.ip_addr)
        h, m, s = f.uptime_s // 3600, (f.uptime_s % 3600) // 60, f.uptime_s % 60
        self._lbl_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")
        self._lbl_heap.setText(f"{f.free_heap:,} bytes")
        self._lbl_tasks.setText(str(f.task_count))

    def set_fw_version(self, major: int, minor: int):
        self._lbl_fw.setText(f"{major}.{minor}")

    def _append_log(self, msg: str):
        self._log.append(msg)


# ══════════════════════════════════════════════════════════════════════════════
#  CAN TX Tab
# ══════════════════════════════════════════════════════════════════════════════

class CANTXTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        box = QGroupBox("Send CAN Frame")
        form = QFormLayout(box)

        self._channel = QComboBox()
        self._channel.addItems(["FDCAN1 (ch 0)", "FDCAN2 (ch 1)"])
        self._id_edit = QLineEdit("0x123")
        self._ext_cb  = QCheckBox("Extended (29-bit)")
        self._fd_cb   = QCheckBox("CAN FD")
        self._brs_cb  = QCheckBox("BRS (bit-rate switch)")
        self._data_edit = QLineEdit("01 02 03 04")
        self._send_btn  = QPushButton("Send")
        self._send_btn.setEnabled(False)
        self._period_box = QGroupBox("Periodic TX")
        self._period_box.setCheckable(True)
        self._period_box.setChecked(False)
        period_form = QFormLayout(self._period_box)
        self._period_ms = QSpinBox()
        self._period_ms.setRange(10, 10000)
        self._period_ms.setValue(100)
        self._period_ms.setSuffix(" ms")
        period_form.addRow("Interval:", self._period_ms)

        form.addRow("Channel:", self._channel)
        form.addRow("CAN ID (hex):", self._id_edit)
        form.addRow("", self._ext_cb)
        form.addRow("", self._fd_cb)
        form.addRow("", self._brs_cb)
        form.addRow("Data (hex bytes):", self._data_edit)
        form.addRow("", self._send_btn)
        layout.addWidget(box)
        layout.addWidget(self._period_box)
        layout.addStretch()

        self._send_btn.clicked.connect(self._send_once)
        self._timer = QTimer()
        self._timer.timeout.connect(self._send_once)
        self._period_box.toggled.connect(self._on_periodic_toggle)

    def set_enabled(self, en: bool):
        self._send_btn.setEnabled(en)

    def _on_periodic_toggle(self, checked: bool):
        if checked:
            self._timer.start(self._period_ms.value())
        else:
            self._timer.stop()

    def _send_once(self):
        if not self._app.client:
            return
        try:
            can_id = int(self._id_edit.text(), 16)
            raw    = self._data_edit.text().strip()
            data   = bytes.fromhex(raw.replace(" ", "").replace("0x", "")) if raw else b""
            ch     = self._channel.currentIndex()
            ext    = self._ext_cb.isChecked()
            self._app.client.send_can(can_id=can_id, data=data, channel=ch, extended=ext)
            signals.log_message.emit(
                f"TX CAN id=0x{can_id:X} ch={ch} data={data.hex()}")
        except Exception as e:
            signals.log_message.emit(f"TX error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  CAN RX Tab
# ══════════════════════════════════════════════════════════════════════════════

MAX_RX_ROWS = 500

class CANRXTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by CAN ID (hex, e.g. 0x123)")
        self._clear_btn = QPushButton("Clear")
        self._pause_cb  = QCheckBox("Pause")
        bar.addWidget(QLabel("Filter:"))
        bar.addWidget(self._filter_edit)
        bar.addWidget(self._clear_btn)
        bar.addWidget(self._pause_cb)
        layout.addLayout(bar)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Timestamp", "Ch", "CAN ID", "DLC", "Data", "Type"])
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setFont(QFont("Monospace", 9))
        layout.addWidget(self._table)

        self._clear_btn.clicked.connect(self._table.clearContents)
        self._clear_btn.clicked.connect(lambda: self._table.setRowCount(0))
        signals.clog_frame.connect(self._on_frame)

    def _on_frame(self, f: CLOGFrame):
        if self._pause_cb.isChecked():
            return
        if f.msg_type not in (CLOGType.RAW_CAN, CLOGType.J1939, CLOGType.EVENT):
            return
        filt = self._filter_edit.text().strip()
        if filt:
            try:
                if f.can_id != int(filt, 16):
                    return
            except ValueError:
                pass

        row = self._table.rowCount()
        if row >= MAX_RX_ROWS:
            self._table.removeRow(0)
            row = self._table.rowCount()
        self._table.insertRow(row)

        ts = time.strftime("%H:%M:%S") + f".{f.ts_nsec // 1_000_000:03d}"
        ext = "x" if f.is_extended else "s"
        if f.msg_type == CLOGType.EVENT:
            tag = f"EVENT(lid={f.channel_id})"
        elif f.msg_type == CLOGType.J1939:
            tag = "J1939"
        else:
            tag = "CAN"
        self._table.setItem(row, 0, QTableWidgetItem(ts))
        self._table.setItem(row, 1, QTableWidgetItem(str(f.channel_id)))
        self._table.setItem(row, 2, QTableWidgetItem(f"0x{f.can_id:08X}{ext}"))
        self._table.setItem(row, 3, QTableWidgetItem(str(f.dlc)))
        self._table.setItem(row, 4, QTableWidgetItem(f.data.hex(" ")))
        item = QTableWidgetItem(tag)
        if f.msg_type == CLOGType.EVENT:
            item.setForeground(QColor(200, 80, 0))
        self._table.setItem(row, 5, item)
        self._table.scrollToBottom()

        if f.msg_type == CLOGType.STATUS and f.fw_major:
            self._app.conn_tab.set_fw_version(f.fw_major, f.fw_minor)


# ══════════════════════════════════════════════════════════════════════════════
#  J1939 TX Tab
# ══════════════════════════════════════════════════════════════════════════════

class J1939TXTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        box = QGroupBox("Send J1939 Frame")
        form = QFormLayout(box)

        self._channel  = QComboBox()
        self._channel.addItems(["FDCAN1 (ch 0)", "FDCAN2 (ch 1)"])

        self._pgn_edit = QLineEdit("0xFEF1")
        self._sa_edit  = QLineEdit("0x00")
        self._da_edit  = QLineEdit("0xFF")
        self._pri_spin = QSpinBox()
        self._pri_spin.setRange(0, 7)
        self._pri_spin.setValue(6)

        self._known_pgn = QComboBox()
        self._known_pgn.addItem("(select known PGN)")
        for pgn, name in WELL_KNOWN_PGNS.items():
            self._known_pgn.addItem(f"0x{pgn:05X} — {name}", pgn)
        self._known_pgn.currentIndexChanged.connect(self._fill_pgn)

        self._data_edit = QLineEdit("FF FF FF FF FF FF FF FF")
        self._send_btn  = QPushButton("Send")
        self._send_btn.setEnabled(False)

        form.addRow("Channel:", self._channel)
        form.addRow("Known PGNs:", self._known_pgn)
        form.addRow("PGN (hex):", self._pgn_edit)
        form.addRow("Source Address:", self._sa_edit)
        form.addRow("Destination Address:", self._da_edit)
        form.addRow("Priority:", self._pri_spin)
        form.addRow("Data (hex bytes):", self._data_edit)
        form.addRow("", self._send_btn)
        layout.addWidget(box)
        layout.addStretch()

        self._send_btn.clicked.connect(self._send)

    def set_enabled(self, en: bool):
        self._send_btn.setEnabled(en)

    def _fill_pgn(self, idx: int):
        if idx <= 0:
            return
        pgn = self._known_pgn.itemData(idx)
        if pgn is not None:
            self._pgn_edit.setText(f"0x{pgn:05X}")

    def _send(self):
        if not self._app.client:
            return
        try:
            pgn  = int(self._pgn_edit.text(), 16)
            sa   = int(self._sa_edit.text(),  16)
            da   = int(self._da_edit.text(),  16)
            pri  = self._pri_spin.value()
            raw  = self._data_edit.text().strip()
            data = bytes.fromhex(raw.replace(" ", "").replace("0x", "")) if raw else b""
            ch   = self._channel.currentIndex()
            self._app.client.send_j1939(pgn=pgn, sa=sa, data=data, da=da,
                                        priority=pri, channel=ch)
            signals.log_message.emit(
                f"TX J1939 PGN=0x{pgn:05X} SA=0x{sa:02X} DA=0x{da:02X} "
                f"data={data.hex()}")
        except Exception as e:
            signals.log_message.emit(f"J1939 TX error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  J1939 RX Tab
# ══════════════════════════════════════════════════════════════════════════════

class J1939RXTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        self._clear_btn = QPushButton("Clear")
        self._pause_cb  = QCheckBox("Pause")
        bar.addWidget(self._clear_btn)
        bar.addWidget(self._pause_cb)
        bar.addStretch()
        layout.addLayout(bar)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["Time", "Ch", "PGN", "PGN Name", "SA", "DA", "Data"])
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setFont(QFont("Monospace", 9))
        layout.addWidget(self._table)

        self._clear_btn.clicked.connect(self._table.clearContents)
        self._clear_btn.clicked.connect(lambda: self._table.setRowCount(0))
        signals.clog_frame.connect(self._on_frame)

    def _on_frame(self, f: CLOGFrame):
        if self._pause_cb.isChecked():
            return
        if f.msg_type != CLOGType.J1939:
            return

        row = self._table.rowCount()
        if row >= MAX_RX_ROWS:
            self._table.removeRow(0)
            row = self._table.rowCount()
        self._table.insertRow(row)

        ts = time.strftime("%H:%M:%S")
        pgn_name = WELL_KNOWN_PGNS.get(f.pgn, "")
        self._table.setItem(row, 0, QTableWidgetItem(ts))
        self._table.setItem(row, 1, QTableWidgetItem(str(f.channel_id)))
        self._table.setItem(row, 2, QTableWidgetItem(f"0x{f.pgn:05X}"))
        self._table.setItem(row, 3, QTableWidgetItem(pgn_name))
        self._table.setItem(row, 4, QTableWidgetItem(f"0x{f.sa:02X}"))
        self._table.setItem(row, 5, QTableWidgetItem(f"0x{f.da:02X}"))
        self._table.setItem(row, 6, QTableWidgetItem(f.data.hex(" ")))
        self._table.scrollToBottom()


# ══════════════════════════════════════════════════════════════════════════════
#  Config / Info Tab
# ══════════════════════════════════════════════════════════════════════════════

class ConfigTab(QWidget):
    def __init__(self, app_: "GatewayApp"):
        super().__init__()
        self._app = app_
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        info_box = QGroupBox("Device Info (HTTP)")
        info_layout = QVBoxLayout(info_box)
        self._info_btn  = QPushButton("Fetch /api/info")
        self._info_text = QTextEdit()
        self._info_text.setReadOnly(True)
        self._info_text.setFont(QFont("Monospace", 9))
        self._info_btn.setEnabled(False)
        info_layout.addWidget(self._info_btn)
        info_layout.addWidget(self._info_text)
        layout.addWidget(info_box)

        tel_box = QGroupBox("J1939 Telemetry")
        tel_layout = QVBoxLayout(tel_box)
        self._tel_btn  = QPushButton("Fetch /api/telemetry")
        self._tel_text = QTextEdit()
        self._tel_text.setReadOnly(True)
        self._tel_text.setFont(QFont("Monospace", 9))
        self._tel_btn.setEnabled(False)
        tel_layout.addWidget(self._tel_btn)
        tel_layout.addWidget(self._tel_text)
        layout.addWidget(tel_box)

        self._info_btn.clicked.connect(self._fetch_info)
        self._tel_btn.clicked.connect(self._fetch_telemetry)

    def set_enabled(self, en: bool):
        self._info_btn.setEnabled(en)
        self._tel_btn.setEnabled(en)

    def _fetch_info(self):
        if not self._app.client:
            return
        try:
            import json
            result = self._app.client.api.get_info()
            self._info_text.setPlainText(json.dumps(result, indent=2))
        except Exception as e:
            self._info_text.setPlainText(f"Error: {e}")

    def _fetch_telemetry(self):
        if not self._app.client:
            return
        try:
            import json
            result = self._app.client.api.get_telemetry()
            self._tel_text.setPlainText(json.dumps(result, indent=2))
        except Exception as e:
            self._tel_text.setPlainText(f"Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Main Application Window
# ══════════════════════════════════════════════════════════════════════════════

class GatewayApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client: Optional[GatewayClient] = None
        self._init_ui()
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._poll_status)

    def _init_ui(self):
        self.setWindowTitle("CAN-ETH Gateway Demo")
        self.resize(900, 650)

        tabs = QTabWidget()
        self.conn_tab    = ConnectionTab(self)
        self.can_tx_tab  = CANTXTab(self)
        self.can_rx_tab  = CANRXTab(self)
        self.j1939_tx    = J1939TXTab(self)
        self.j1939_rx    = J1939RXTab(self)
        self.config_tab  = ConfigTab(self)

        tabs.addTab(self.conn_tab,   "Connection")
        tabs.addTab(self.can_tx_tab, "CAN TX")
        tabs.addTab(self.can_rx_tab, "CAN RX")
        tabs.addTab(self.j1939_tx,   "J1939 TX")
        tabs.addTab(self.j1939_rx,   "J1939 RX")
        tabs.addTab(self.config_tab, "Config / Info")

        self.setCentralWidget(tabs)
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Disconnected")

    def connect(self, ip: str) -> None:
        if self.client:
            self.disconnect()
        try:
            self.client = GatewayClient(host=ip)
            self.client.clog.on_frame   = lambda f: signals.clog_frame.emit(f)
            self.client.status.on_frame = lambda f: signals.status_frame.emit(f)
            self.client.open()

            self.can_tx_tab.set_enabled(True)
            self.j1939_tx.set_enabled(True)
            self.config_tab.set_enabled(True)
            self._statusbar.showMessage(f"Connected to {ip}")
            signals.log_message.emit(f"Connected to {ip}")
            self._status_timer.start(1000)
        except Exception as e:
            self.client = None
            QMessageBox.critical(self, "Connection failed", str(e))

    def disconnect(self) -> None:
        self._status_timer.stop()
        if self.client:
            self.client.close()
            self.client = None
        self.can_tx_tab.set_enabled(False)
        self.j1939_tx.set_enabled(False)
        self.config_tab.set_enabled(False)
        self._statusbar.showMessage("Disconnected")
        signals.log_message.emit("Disconnected")

    def _poll_status(self) -> None:
        if not self.client:
            return
        s = self.client.last_status
        if s:
            self._statusbar.showMessage(
                f"Connected | uptime {s.uptime_s}s | heap {s.free_heap:,}B | {s.ip_addr}")

    def closeEvent(self, event):
        self.disconnect()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = GatewayApp()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
