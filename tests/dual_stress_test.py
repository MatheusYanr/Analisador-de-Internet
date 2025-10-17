"""Stress test the dual monitor loop with mocked ping operations."""
import sys
import time
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from monitoramento import DualWiFiMonitorManager, NetworkMonitor


def mocked_ping_host(self, host):
    """Return a synthetic latency in milliseconds."""
    # Simulate sporadic packet loss
    if random.random() < 0.1:
        return None
    return random.uniform(50.0, 140.0)


def noop_update_filename(self):
    """Bypass netsh call to keep test deterministic."""
    self.anomaly_file = "logs/anomalias_TESTE.csv"


def run():
    original_ping_host = NetworkMonitor.ping_host
    original_update_filename = NetworkMonitor.update_anomaly_filename_with_wifi

    NetworkMonitor.ping_host = mocked_ping_host  # type: ignore
    NetworkMonitor.update_anomaly_filename_with_wifi = noop_update_filename  # type: ignore

    try:
        base_monitor = NetworkMonitor()
        base_monitor.anomaly_threshold = 120
        base_monitor.anomaly_min_increase_percent = 25.0
        base_monitor.anomaly_min_pings = 4

        manager = DualWiFiMonitorManager()
        monitor_a = manager.add_monitor("StressSSID_A", "8.8.8.8", 0.2, base_monitor)
        monitor_b = manager.add_monitor("StressSSID_B", "1.1.1.1", 0.2, base_monitor)

        logs = {"A": [], "B": []}

        def cb_a(data):
            logs["A"].append(data)

        def cb_b(data):
            logs["B"].append(data)

        manager.start_monitor("StressSSID_A", cb_a)
        manager.start_monitor("StressSSID_B", cb_b)

        time.sleep(5)

        manager.stop_all()

        total_a = monitor_a.stats["total_pings"]
        total_b = monitor_b.stats["total_pings"]

        print(f"Monitor A pings: {total_a}")
        print(f"Monitor B pings: {total_b}")
        print(f"Callbacks A: {len(logs['A'])}")
        print(f"Callbacks B: {len(logs['B'])}")

        assert total_a > 0, "Monitor A did not record pings"
        assert total_b > 0, "Monitor B did not record pings"
        assert len(logs['A']) == total_a, "Mismatch between stats and callback count for A"
        assert len(logs['B']) == total_b, "Mismatch between stats and callback count for B"
    finally:
        NetworkMonitor.ping_host = original_ping_host
        NetworkMonitor.update_anomaly_filename_with_wifi = original_update_filename


if __name__ == "__main__":
    run()
    print("✅ Stress test completed successfully")
