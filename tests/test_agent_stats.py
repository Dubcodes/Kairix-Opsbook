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
from kairix.main import _match_agent_device, _stats_snapshot_state
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


if __name__ == "__main__":
    unittest.main()
