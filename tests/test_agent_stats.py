import os
from datetime import timedelta
from pathlib import Path
import unittest

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
if not (Path.cwd() / "static").exists() and (APP_ROOT / "static").exists():
    os.chdir(APP_ROOT)

from kairix import models
from kairix.main import _match_agent_device, _stats_monitor_payload, _stats_snapshot_state
from kairix.security import now_utc


class AgentStatsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:")

        @event.listens_for(self.engine, "connect")
        def _enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        models.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self) -> None:
        models.Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_agent_matches_existing_device_without_creating_records(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Windows Lab", slug="windows-lab", hostname="WIN-LAB", primary_ip="192.168.1.42")
            session.add(device)
            session.commit()

            self.assertEqual(_match_agent_device(session, {"device_id": device.id}).id, device.id)
            self.assertEqual(_match_agent_device(session, {"primary_ip": "192.168.1.42"}).id, device.id)
            self.assertEqual(_match_agent_device(session, {"hostname": "win-lab"}).id, device.id)
            self.assertIsNone(_match_agent_device(session, {"hostname": "new-device"}))
            self.assertEqual(session.query(models.Device).count(), 1)
        finally:
            session.close()

    def test_stats_snapshot_state_ages_cleanly(self) -> None:
        fresh = models.DeviceStatSnapshot(device_id=1, created_at=now_utc() - timedelta(minutes=4))
        stale = models.DeviceStatSnapshot(device_id=1, created_at=now_utc() - timedelta(minutes=30))
        old = models.DeviceStatSnapshot(device_id=1, created_at=now_utc() - timedelta(hours=2))

        self.assertEqual(_stats_snapshot_state(None)["state"], "unknown")
        self.assertEqual(_stats_snapshot_state(fresh)["state"], "good")
        self.assertEqual(_stats_snapshot_state(stale)["state"], "slow")
        self.assertEqual(_stats_snapshot_state(old)["state"], "bad")

    def test_stats_payload_omits_devices_that_never_reported(self) -> None:
        session = self.Session()
        try:
            reporting = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            silent = models.Device(name="Silent Box", slug="silent-box", primary_ip="192.168.0.250")
            session.add_all([reporting, silent])
            session.flush()
            session.add(
                models.DeviceStatSnapshot(
                    device_id=reporting.id,
                    cpu_percent=12,
                    memory_percent=34,
                    root_disk_percent=56,
                    load_1=0.42,
                    created_at=now_utc(),
                    observed_at=now_utc(),
                )
            )
            session.commit()

            payload = _stats_monitor_payload(session, [reporting, silent], 8)

            self.assertEqual(payload["counts"]["reporting"], 1)
            self.assertEqual([item["name"] for item in payload["devices"]], ["Moxxie"])
            self.assertEqual(payload["devices"][0]["latest"]["labels"]["cpu"], "12%")
            self.assertEqual(payload["devices"][0]["latest"]["labels"]["load"], "0.42")
            self.assertEqual(payload["overview_metrics"], ["cpu", "memory", "disk", "load"])
            self.assertIn("network", payload["detail_metrics"])
        finally:
            session.close()

    def test_stats_payload_includes_extended_metric_labels_and_details(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            session.add(device)
            session.flush()
            session.add(
                models.DeviceStatSnapshot(
                    device_id=device.id,
                    cpu_percent=12,
                    cpu_count=4,
                    memory_percent=34,
                    memory_used_bytes=4 * 1024**3,
                    memory_total_bytes=8 * 1024**3,
                    swap_percent=25,
                    swap_used_bytes=512 * 1024**2,
                    swap_total_bytes=2 * 1024**3,
                    root_disk_percent=56,
                    root_disk_used_bytes=56 * 1024**3,
                    root_disk_total_bytes=100 * 1024**3,
                    load_1=1.0,
                    load_per_core=0.25,
                    network_rx_bps=2048,
                    network_tx_bps=1024,
                    docker_running_count=2,
                    docker_stopped_count=1,
                    docker_unhealthy_count=1,
                    docker_total_count=3,
                    created_at=now_utc() - timedelta(minutes=20),
                    observed_at=now_utc() - timedelta(minutes=20),
                    payload_json={
                        "disks": [
                            {"mountpoint": "/", "used_bytes": 56 * 1024**3, "total_bytes": 100 * 1024**3, "percent": 56},
                            {"mountpoint": "/data", "used_bytes": 1 * 1024**3, "total_bytes": 2 * 1024**3, "percent": 50},
                        ],
                        "network": {"interfaces": [{"name": "eno1", "rx_bytes": 1000, "tx_bytes": 2000}]},
                        "docker": {
                            "enabled": True,
                            "running": 2,
                            "stopped": 1,
                            "unhealthy": 1,
                            "total": 3,
                            "containers": [{"name": "web", "status": "Up", "image": "example/web:latest"}],
                        },
                    },
                )
            )
            session.commit()

            latest = _stats_monitor_payload(session, [device], 8)["devices"][0]["latest"]

            self.assertEqual(latest["labels"]["swap"], "25%")
            self.assertEqual(latest["labels"]["load_core"], "0.25")
            self.assertEqual(latest["labels"]["network"], "3.0 KB/s")
            self.assertEqual(latest["labels"]["freshness_detail"], "3 missed report(s)")
            self.assertEqual(latest["labels"]["docker"], "1 bad")
            self.assertEqual(latest["details"]["disks"][1]["label"], "/data")
            self.assertEqual(latest["details"]["network"][0]["label"], "eno1")
            self.assertTrue(latest["details"]["docker"]["enabled"])
        finally:
            session.close()

    def test_stats_payload_graph_series_respects_window(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            session.add(device)
            session.flush()
            old = models.DeviceStatSnapshot(
                device_id=device.id,
                cpu_percent=99,
                created_at=now_utc() - timedelta(hours=9),
                observed_at=now_utc() - timedelta(hours=9),
            )
            recent = models.DeviceStatSnapshot(
                device_id=device.id,
                cpu_percent=22,
                created_at=now_utc() - timedelta(minutes=5),
                observed_at=now_utc() - timedelta(minutes=5),
            )
            session.add_all([old, recent])
            session.commit()

            payload = _stats_monitor_payload(session, [device], 8)
            series = payload["devices"][0]["series"]

            self.assertEqual(len(series), 1)
            self.assertEqual(series[0]["cpu_percent"], 22)
            self.assertEqual(payload["devices"][0]["latest"]["cpu_percent"], 22)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
