"""Test that dual monitors maintain independent data even with same SSID."""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from monitoramento import DualWiFiMonitorManager, NetworkMonitor


def test_independent_monitors_same_ssid():
    """Ensure two monitors for same SSID maintain separate ping_history."""
    base_monitor = NetworkMonitor()
    base_monitor.anomaly_threshold = 100
    base_monitor.anomaly_min_increase_percent = 30.0
    base_monitor.anomaly_min_pings = 4
    
    manager = DualWiFiMonitorManager()
    
    # Create two monitors for SAME SSID with force_new=True
    monitor_a = manager.add_monitor("SameSSID", "8.8.8.8", 1.0, base_monitor, force_new=True)
    monitor_b = manager.add_monitor("SameSSID", "1.1.1.1", 1.0, base_monitor, force_new=True)
    
    # Verify they are different objects
    assert monitor_a is not monitor_b, "Monitors should be different objects"
    assert id(monitor_a.ping_history) != id(monitor_b.ping_history), "ping_history should be independent"
    
    # Add different data
    monitor_a.ping_history.append(50.0)
    monitor_a.ping_history.append(55.0)
    
    monitor_b.ping_history.append(100.0)
    monitor_b.ping_history.append(110.0)
    
    # Verify independence
    assert len(monitor_a.ping_history) == 2, f"Monitor A should have 2 pings, got {len(monitor_a.ping_history)}"
    assert len(monitor_b.ping_history) == 2, f"Monitor B should have 2 pings, got {len(monitor_b.ping_history)}"
    assert list(monitor_a.ping_history) == [50.0, 55.0], f"Monitor A data corrupted: {list(monitor_a.ping_history)}"
    assert list(monitor_b.ping_history) == [100.0, 110.0], f"Monitor B data corrupted: {list(monitor_b.ping_history)}"
    
    # Verify configurations were copied
    assert monitor_a.anomaly_threshold == 100
    assert monitor_b.anomaly_threshold == 100
    assert monitor_a.anomaly_min_increase_percent == 30.0
    assert monitor_b.anomaly_min_increase_percent == 30.0
    assert monitor_a.anomaly_min_pings == 4
    assert monitor_b.anomaly_min_pings == 4
    
    print("✅ Monitors are truly independent")
    print(f"   Monitor A: {len(monitor_a.ping_history)} pings, data: {list(monitor_a.ping_history)}")
    print(f"   Monitor B: {len(monitor_b.ping_history)} pings, data: {list(monitor_b.ping_history)}")


if __name__ == "__main__":
    test_independent_monitors_same_ssid()
    print("✅ All independence tests passed")
