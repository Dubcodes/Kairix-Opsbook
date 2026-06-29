import os
from datetime import timedelta
from pathlib import Path
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
if not (Path.cwd() / "static").exists() and (APP_ROOT / "static").exists():
    os.chdir(APP_ROOT)

from kairix import models
from kairix.exporter import build_backup_payload
from kairix.main import _prune_stats
from kairix.security import now_utc


class EmergencyExportSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self) -> None:
        models.Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_backup_excludes_high_frequency_stats_telemetry(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Test Host", slug="test-host")
            session.add(device)
            session.flush()
            session.add(
                models.DeviceStatSnapshot(
                    device_id=device.id,
                    observed_at=now_utc(),
                    payload_json={"cpu": {"percent": 42}},
                )
            )
            session.commit()

            payload = build_backup_payload(session)

            self.assertNotIn("device_stat_snapshots", payload["tables"])
            self.assertIn("device_stat_snapshots", payload["metadata"]["excluded_tables"])
            self.assertEqual(len(payload["tables"]["devices"]), 1)
        finally:
            session.close()

    def test_stats_retention_removes_only_expired_rows(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Test Host", slug="test-host")
            session.add(device)
            session.flush()
            session.add_all(
                [
                    models.DeviceStatSnapshot(
                        device_id=device.id,
                        observed_at=now_utc() - timedelta(days=31),
                        payload_json={},
                    ),
                    models.DeviceStatSnapshot(
                        device_id=device.id,
                        observed_at=now_utc() - timedelta(days=2),
                        payload_json={},
                    ),
                ]
            )
            session.commit()

            deleted = _prune_stats(session, days=30)
            session.commit()

            self.assertEqual(deleted, 1)
            self.assertEqual(session.query(models.DeviceStatSnapshot).count(), 1)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
