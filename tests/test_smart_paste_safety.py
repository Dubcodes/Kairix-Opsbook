import os
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
from kairix.main import _annotate_import_suggestions, _move_device_records_to_preserved_device, _sync_credential_login_endpoint
from kairix.parser import parse_smart_paste


class SmartPasteSafetyTest(unittest.TestCase):
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

    def test_inventory_keeps_host_name_when_container_is_beszel(self) -> None:
        text = """=== HOST ===
 Static hostname: moxxie
Operating System: Debian GNU/Linux 12 (bookworm)

=== IP ADDRESSES ===
eno1             UP             192.168.0.238/24

=== DOCKER CONTAINERS ===
NAMES          IMAGE                         STATUS      PORTS
beszel-agent   henrygd/beszel-agent:latest   Up 6 hours
beszel         henrygd/beszel:latest         Up 7 hours  0.0.0.0:8090->8090/tcp
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "moxxie")
        self.assertEqual(parsed["device"]["primary_ip"], "192.168.0.238")
        self.assertIn("Beszel", {item["name"] for item in parsed["services"]})

    def test_docker_only_paste_does_not_guess_device_name_from_container(self) -> None:
        text = """=== DOCKER CONTAINERS ===
NAMES          IMAGE                         STATUS      PORTS
beszel-agent   henrygd/beszel-agent:latest   Up 6 hours
beszel         henrygd/beszel:latest         Up 7 hours  0.0.0.0:8090->8090/tcp
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "")
        self.assertIn("Beszel", {item["name"] for item in parsed["services"]})

    def test_cloudflare_tunnel_output_keeps_source_context(self) -> None:
        text = """=== CLOUDFLARE TUNNELS ===

--- temp-deputy-roster-view-url ---
https://bloggers-cst-segments-disposal.trycloudflare.com

--- kairix-judgenburn-temp-control-url ---
https://consistently-briefly-coupons-header.trycloudflare.com

--- kairix-judgenburn-temp-public-url ---
https://shower-centers-occupational-fax.trycloudflare.com
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "")
        self.assertEqual(len(parsed["urls"]), 3)
        deputy_url = next(item for item in parsed["urls"] if "bloggers-cst" in item["url"])
        self.assertEqual(deputy_url["source_label"], "temp-deputy-roster-view-url")
        self.assertIn("--- temp-deputy-roster-view-url ---", deputy_url["source_excerpt"])
        self.assertIn(deputy_url["url"], deputy_url["source_excerpt"])

    def test_cloudflare_tunnel_output_suggests_existing_services(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie")
            deputy = models.Service(device=device, name="Deputy Roster View Deputy Roster View 1", slug="deputy-roster")
            public = models.Service(device=device, name="Kairix Judgenburn Public 1", slug="judgenburn-public")
            web = models.Service(device=device, name="Kairix Judgenburn Web 1", slug="judgenburn-web")
            db_service = models.Service(device=device, name="Kairix Judgenburn Db 1", slug="judgenburn-db")
            session.add_all([device, deputy, public, web, db_service])
            session.commit()

            parsed = parse_smart_paste(
                """=== CLOUDFLARE TUNNELS ===

--- temp-deputy-roster-view-url ---
https://bloggers-cst-segments-disposal.trycloudflare.com

--- kairix-judgenburn-temp-control-url ---
https://consistently-briefly-coupons-header.trycloudflare.com

--- kairix-judgenburn-temp-public-url ---
https://shower-centers-occupational-fax.trycloudflare.com
"""
            )
            annotated = _annotate_import_suggestions(session, parsed)

            suggestions = {item["source_label"]: item["suggested_service_id"] for item in annotated["urls"]}
            self.assertEqual(suggestions["temp-deputy-roster-view-url"], deputy.id)
            self.assertEqual(suggestions["kairix-judgenburn-temp-public-url"], public.id)
            self.assertEqual(suggestions["kairix-judgenburn-temp-control-url"], web.id)
        finally:
            session.close()

    def test_cloudflare_tunnel_output_keeps_latest_url_per_container(self) -> None:
        parsed = parse_smart_paste(
            """=== CLOUDFLARE TUNNELS ===

--- kairix-temp-tunnel ---
https://involved-risks-roger-salad.trycloudflare.com
https://involved-risks-roger-salad.trycloudflare.com

--- people-temp-tunnel-central ---
https://clusters-component-barrier-clearing.trycloudflare.com
https://sparc-sustainable-bracket-eden.trycloudflare.com

--- people-temp-tunnel-dunedin ---
https://objects-chances-journalism-repairs.trycloudflare.com
https://riding-stable-hair-biggest.trycloudflare.com
"""
        )

        urls_by_source = {item["source_label"]: item for item in parsed["urls"]}
        self.assertEqual(len(parsed["urls"]), 3)
        self.assertEqual(
            urls_by_source["people-temp-tunnel-central"]["url"],
            "https://sparc-sustainable-bracket-eden.trycloudflare.com",
        )
        self.assertEqual(
            urls_by_source["people-temp-tunnel-dunedin"]["url"],
            "https://riding-stable-hair-biggest.trycloudflare.com",
        )
        self.assertEqual(
            urls_by_source["people-temp-tunnel-central"]["history_urls"],
            [
                "https://clusters-component-barrier-clearing.trycloudflare.com",
                "https://sparc-sustainable-bracket-eden.trycloudflare.com",
            ],
        )

    def test_cloudflare_tunnels_do_not_collapse_people_regions(self) -> None:
        text = """=== HOST ===
 Static hostname: PortainServer

=== IP ADDRESSES ===
eno1 UP 192.168.0.205/24

=== DOCKER CONTAINERS ===
NAMES                             IMAGE                         STATUS      PORTS
people-temp-tunnel-central        cloudflare/cloudflared:latest Up 11 days
people-temp-tunnel-dunedin        cloudflare/cloudflared:latest Up 11 days
people-temp-tunnel-northern       cloudflare/cloudflared:latest Up 11 days
people-temp-tunnel-christchurch   cloudflare/cloudflared:latest Up 11 days
people-app-northern               python:3.11-slim              Up 7 minutes 0.0.0.0:8090->8000/tcp
people-app-christchurch           python:3.11-slim              Up 21 minutes 0.0.0.0:8092->8000/tcp
people-db                         postgres:15                   Up 4 days    0.0.0.0:5433->5432/tcp

=== DOCKER COMPOSE PROJECTS ===
NAME                STATUS              CONFIG FILES
people-system       running(7)          /data/compose/39/docker-compose.yml

=== CLOUDFLARE TUNNELS ===

--- people-temp-tunnel-central ---
https://clusters-component-barrier-clearing.trycloudflare.com
https://sparc-sustainable-bracket-eden.trycloudflare.com

--- people-temp-tunnel-dunedin ---
https://objects-chances-journalism-repairs.trycloudflare.com
https://riding-stable-hair-biggest.trycloudflare.com

--- people-temp-tunnel-northern ---
https://tips-eco-lot-hunter.trycloudflare.com

--- people-temp-tunnel-christchurch ---
https://replied-dust-calculator-weblog.trycloudflare.com
https://microphone-acquisition-ons-spine.trycloudflare.com
"""
        parsed = parse_smart_paste(text)
        services_by_name = {item["name"]: item for item in parsed["services"]}

        self.assertEqual(
            services_by_name["People Temp Tunnel Central"]["urls"][0]["url"],
            "https://sparc-sustainable-bracket-eden.trycloudflare.com",
        )
        self.assertEqual(
            services_by_name["People Temp Tunnel Dunedin"]["urls"][0]["url"],
            "https://riding-stable-hair-biggest.trycloudflare.com",
        )
        self.assertEqual(
            services_by_name["People App Northern"]["urls"][-1]["url"],
            "https://tips-eco-lot-hunter.trycloudflare.com",
        )
        self.assertEqual(
            services_by_name["People App Christchurch"]["urls"][-1]["url"],
            "https://microphone-acquisition-ons-spine.trycloudflare.com",
        )

    def test_credential_login_url_creates_service_url_and_port(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie")
            service = models.Service(device=device, name="Beszel", slug="beszel")
            credential = models.Credential(
                service=service,
                label="Beszel admin",
                username="admin",
                secret_encrypted="encrypted",
                login_url="192.168.0.238:8090",
            )
            session.add_all([device, service, credential])
            session.flush()

            changed = _sync_credential_login_endpoint(session, credential)
            session.commit()

            self.assertEqual(credential.login_url, "http://192.168.0.238:8090")
            self.assertEqual(device.primary_ip, "192.168.0.238")
            self.assertEqual(service.local_url, "http://192.168.0.238:8090")
            self.assertEqual(changed["ports"], 1)
            port = session.query(models.Port).one()
            self.assertEqual(port.device_id, device.id)
            self.assertEqual(port.service_id, service.id)
            self.assertEqual(port.host_port, 8090)
        finally:
            session.close()

    def test_device_delete_preservation_moves_linked_records_to_holding_device(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie")
            service = models.Service(device=device, name="Beszel", slug="beszel")
            credential = models.Credential(
                device=device,
                service=service,
                label="Beszel admin",
                secret_encrypted="encrypted",
            )
            port = models.Port(device=device, service=service, host_port=8090)
            url = models.Url(device=device, service=service, label="Beszel", url="http://192.168.0.238:8090")
            image = models.DeviceImage(device=device, name="Receipt", stored_filename="receipt.png")
            note = models.Note(object_type="device", object_id=1, title="Old device note", body="Keep this")
            command = models.Command(
                name="Check host",
                category="Linux",
                applies_to_type="device",
                applies_to_id=1,
                command_template="uptime",
            )
            session.add_all([device, service, credential, port, url, image])
            session.flush()
            note.object_id = device.id
            command.applies_to_id = device.id
            session.add_all([note, command])
            session.commit()

            holding = _move_device_records_to_preserved_device(session, device)
            session.delete(device)
            session.commit()

            self.assertEqual(session.query(models.Device).count(), 1)
            self.assertEqual(session.query(models.Device).one().id, holding.id)
            self.assertEqual(session.query(models.Service).one().device_id, holding.id)
            self.assertEqual(session.query(models.Credential).one().service_id, service.id)
            self.assertEqual(session.query(models.Port).one().device_id, holding.id)
            self.assertEqual(session.query(models.Url).one().device_id, holding.id)
            self.assertEqual(session.query(models.DeviceImage).one().device_id, holding.id)
            self.assertEqual(session.query(models.Note).one().object_id, holding.id)
            self.assertEqual(session.query(models.Command).one().applies_to_id, holding.id)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
