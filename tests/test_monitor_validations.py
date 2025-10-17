"""Sanity checks for monitoramento mechanics."""
import os
import sys
import tkinter as tk
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from monitoramento import DualWiFiMonitorManager, MonitorGUI, NetworkMonitor


def _make_anomaly_payload():
    now = datetime.now()
    return {
        "start_time": now,
        "end_time": now,
        "duration_seconds": 5.0,
        "avg_latency": 150.0,
        "min_latency": 120.0,
        "max_latency": 180.0,
        "pings_affected": 6,
        "start_ping_number": 1,
        "detection_method": "threshold",
        "baseline_avg": 60.0,
        "baseline_min": 50.0,
        "baseline_max": 70.0,
        "increase_percent": 150.0,
    }


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def check_dual_configuration_copy():
    manager = DualWiFiMonitorManager()
    primary = NetworkMonitor()
    primary.anomaly_threshold = 90
    primary.anomaly_min_increase_percent = 40.0
    primary.anomaly_min_pings = 7
    primary.anomaly_deviation_multiplier = 2.8
    primary.anomaly_min_samples = 22
    primary.anomaly_min_consecutive_normal = 11

    monitor = manager.add_monitor("TestSSID_A", "1.1.1.1", 1.5, primary)

    _assert(monitor.anomaly_threshold == 90, "Threshold not copied")
    _assert(monitor.anomaly_min_increase_percent == 40.0, "Increase percent mismatch")
    _assert(monitor.anomaly_min_pings == 7, "Minimum pings mismatch")
    _assert(monitor.anomaly_deviation_multiplier == 2.8, "Deviation multiplier mismatch")
    _assert(monitor.anomaly_min_samples == 22, "Minimum samples mismatch")
    _assert(monitor.anomaly_min_consecutive_normal == 11, "Consecutive normal mismatch")
    _assert(monitor.enable_wifi_reconnect is False, "Reconnect should stay disabled")
    _assert(monitor.enable_sound_alerts is False, "Sound alerts should stay disabled")
    _assert("logs/anomalias_TestSSID_A" in monitor.anomaly_file, "Anomaly file naming broken")


def check_anomaly_file_rollover():
    monitor = NetworkMonitor(monitor_id="rollover", wifi_ssid="TestSSID_B")
    monitor.anomaly_file = "logs/anomalias_TestSSID_B_1900-01-01.csv"
    payload = _make_anomaly_payload()
    monitor.save_anomaly(payload)

    current_tag = datetime.now().strftime("%Y-%m-%d")
    _assert(current_tag in monitor.anomaly_file, "Anomaly file not updated to current date")
    _assert(os.path.exists(monitor.anomaly_file), "Anomaly file not created")

    # Clean up test artifact
    try:
        os.remove(monitor.anomaly_file)
    except OSError:
        pass


def check_dual_graph_lines():
    root = tk.Tk()
    root.withdraw()
    gui = MonitorGUI(root)

    monitor = NetworkMonitor(monitor_id="graph_test", wifi_ssid="GraphSSID")
    monitor.monitoring = True
    monitor.anomaly_threshold = 200
    monitor.ping_history.extend([150, 210, 190, 175])

    gui.dual_monitors[2] = monitor
    gui.dual_update_graph(2)

    lines = gui.dual_ax2.lines
    labels = {line.get_label() for line in lines}

    _assert(len(lines) == 3, "Expected latency, threshold, and average lines")
    _assert(any("Limiar de Anomalia" in label for label in labels), "Missing threshold annotation")
    _assert(any("Média" in label for label in labels), "Missing average annotation")

    root.destroy()


if __name__ == "__main__":
    print("▶️ Validando configurações do monitor dual...")
    check_dual_configuration_copy()
    print("   OK")

    print("▶️ Verificando atualização de arquivo de anomalia...")
    check_anomaly_file_rollover()
    print("   OK")

    print("▶️ Conferindo linhas do gráfico dual...")
    check_dual_graph_lines()
    print("   OK")

    print("✅ Todos os testes concluídos sem falhas.")
