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
from kairix.main import _annotate_import_suggestions, _move_device_records_to_preserved_device, _secure_parsed_for_storage, _sync_credential_login_endpoint
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

    def test_github_token_paste_extracts_name_and_expiry(self) -> None:
        text = """deputy-ai
Never used •Expires on Mon, Jul 13 2026
Make sure to copy your personal access token now as you will not be able to see this again.
github_pat_11EXAMPLE0RVJrPrvsSNHo_dUWI8Jaxx6k4p9XbQMRnBotJmjFXhwD0F3MxMVNzW1OOYSFSF5XLLGVElxW
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(len(parsed["tokens"]), 1)
        self.assertEqual(parsed["device"]["name"], "")
        self.assertEqual(parsed["services"], [])
        self.assertEqual(parsed["ports"], [])
        self.assertEqual(parsed["credentials"], [])
        token = parsed["tokens"][0]
        self.assertEqual(token["label"], "deputy-ai")
        self.assertEqual(token["service_name"], "deputy ai")
        self.assertEqual(token["security_level"], "high")
        self.assertTrue(token["expires_at"].startswith("2026-07-13"))

    def test_github_token_page_with_account_does_not_create_fake_records(self) -> None:
        text = """@Dubcodes
forcodex
github_pat_11EXAMPLE0RVJrPrvsSNHo_dUWI8Jaxx6k4p9XbQMRnBotJmjFXhwD0F3MxMVNzW1OOYSFSF5XLLGVElxW
Expires on Tue, Jul 28 2026
Make sure to copy your personal access token now as you will not be able to see this again.

github_pat_11EXAMPLE0RVJrPrvsSNHo_dUWI8Jaxx6k4p9XbQMRnBotJmjFXhwD0F3MxMVNzW1OOYSFSF5XLLGVElxW
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "")
        self.assertEqual(parsed["services"], [])
        self.assertEqual(parsed["ports"], [])
        self.assertEqual(parsed["urls"], [])
        self.assertEqual(parsed["credentials"], [])
        self.assertEqual(len(parsed["tokens"]), 1)
        token = parsed["tokens"][0]
        self.assertEqual(token["label"], "forcodex")
        self.assertEqual(token["username"], "@Dubcodes")
        self.assertTrue(token["expires_at"].startswith("2026-07-28"))

    def test_common_provider_tokens_are_detected_without_fake_services(self) -> None:
        text = """GitLab deploy token
Expires: 2026-08-01
glpat-1234567890abcdef1234

Cloudflare DNS automation
cfut_1234567890abcdefghijklmnopqrstuvwxyzABCD

OpenAI batch processor
sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDE
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "")
        self.assertEqual(parsed["services"], [])
        self.assertEqual(parsed["ports"], [])
        self.assertEqual(parsed["credentials"], [])
        labels = {item["label"] for item in parsed["tokens"]}
        self.assertIn("GitLab deploy token", labels)
        self.assertIn("Cloudflare DNS automation", labels)
        self.assertIn("OpenAI batch processor", labels)

    def test_windows_systeminfo_style_host_and_os(self) -> None:
        text = """Host Name:                 WIN-OPS-01
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22631 N/A Build 22631
IPv4 Address. . . . . . . . . . . : 192.168.1.42
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "WIN-OPS-01")
        self.assertEqual(parsed["device"]["primary_ip"], "192.168.1.42")
        self.assertIn("Microsoft Windows 11 Pro", parsed["device"]["os_name"])

    def test_macos_sw_vers_style_host_and_os(self) -> None:
        text = """ComputerName: Studio Mac
ProductName: macOS
ProductVersion: 14.5
IPv4: 10.0.0.12
"""
        parsed = parse_smart_paste(text)

        self.assertEqual(parsed["device"]["name"], "Studio Mac")
        self.assertEqual(parsed["device"]["primary_ip"], "10.0.0.12")
        self.assertEqual(parsed["device"]["os_name"], "macOS 14.5")

    def test_default_docker_ps_rows_create_services_and_ports(self) -> None:
        text = """=== HOST ===
Hostname: docker-host

=== IP ADDRESSES ===
eth0 UP 192.168.1.20/24

=== DOCKER CONTAINERS ===
CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS                                      NAMES
2c3032c7d8a1   nginx:alpine   "/docker-entrypoint..."  2 hours ago    Up 2 hours    0.0.0.0:8088->80/tcp, :::8088->80/tcp      web-proxy
"""
        parsed = parse_smart_paste(text)
        service = next(item for item in parsed["services"] if item["name"] == "Web Proxy")

        self.assertEqual(service["container_name"], "web-proxy")
        self.assertEqual(service["image"], "nginx:alpine")
        self.assertEqual(service["ports"][0]["host_port"], 8088)
        self.assertEqual(service["ports"][0]["internal_port"], 80)
        self.assertEqual(service["urls"][0]["url"], "http://192.168.1.20:8088/")

    def test_inventory_session_lines_do_not_create_login_credentials(self) -> None:
        text = """login as: mainuser
mainuser@192.168.0.238's password:
Linux moxxie 6.1.0-48-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.172-1 (2026-05-15) x86_64
Last login: Fri Jun  5 15:18:59 2026 from 192.168.0.244
mainuser@moxxie:~$ printf '=== HOST ===\\n'; hostnamectl 2>/dev/null || hostname
=== HOST ===
 Static hostname: moxxie
Operating System: Debian GNU/Linux 12 (bookworm)

=== IP ADDRESSES ===
eno1             UP             192.168.0.238/24

=== DOCKER CONTAINERS ===
NAMES              IMAGE                                      STATUS      PORTS
kairix-opsbook-app ghcr.io/dubcodes/kairix-opsbook:latest     Up 7 hours  0.0.0.0:8095->8000/tcp
"""
        parsed = parse_smart_paste(text)

        usernames = {item.get("username", "").lower() for item in parsed["credentials"]}
        labels = {item.get("label", "").lower() for item in parsed["credentials"]}
        self.assertNotIn("mainuser", usernames)
        self.assertNotIn("fri", usernames)
        self.assertNotIn("mainuser login", labels)
        self.assertNotIn("fri login", labels)

    def test_syncthing_relay_ports_do_not_create_web_urls(self) -> None:
        text = """=== HOST ===
 Static hostname: PortainServer

=== IP ADDRESSES ===
eno1             UP             192.168.0.205/24

=== DOCKER CONTAINERS ===
NAMES             IMAGE                         STATUS      PORTS
syncthing-relay   syncthing/relaysrv:latest     Up 2 days   0.0.0.0:22067->22067/tcp, 0.0.0.0:22070->22070/tcp
"""
        parsed = parse_smart_paste(text)
        relay = next(item for item in parsed["services"] if item["name"] == "Syncthing Relay")

        self.assertEqual(relay["urls"], [])
        self.assertEqual(
            {(port["host_port"], port["internal_port"]) for port in relay["ports"]},
            {(22067, 22067), (22070, 22070)},
        )

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

    def test_cloudflare_tunnel_shell_output_with_duplicate_urls_is_safe(self) -> None:
        text = """mainuser@PortainServer:~$ printf '=== CLOUDFLARE TUNNELS ===\\n'
for container in 'kairix-temp-tunnel' 'people-temp-tunnel-central' 'people-temp-tunnel-dunedin' 'people-temp-tunnel-northern' 'people-temp-tunnel-christchurch'; do
  printf '\\n--- %s ---\\n' "$container"
  docker logs --tail 300 "$container" 2>&1 | grep -Eo 'https://[-A-Za-z0-9.]+\\.trycloudflare\\.com' | tail -n 3
done
=== CLOUDFLARE TUNNELS ===

--- kairix-temp-tunnel ---
https://involved-risks-roger-salad.trycloudflare.com
https://involved-risks-roger-salad.trycloudflare.com
https://involved-risks-roger-salad.trycloudflare.com

--- people-temp-tunnel-central ---
https://sparc-sustainable-bracket-eden.trycloudflare.com
https://sparc-sustainable-bracket-eden.trycloudflare.com
https://sparc-sustainable-bracket-eden.trycloudflare.com

--- people-temp-tunnel-dunedin ---
https://riding-stable-hair-biggest.trycloudflare.com
https://riding-stable-hair-biggest.trycloudflare.com
https://riding-stable-hair-biggest.trycloudflare.com

--- people-temp-tunnel-northern ---
https://tips-eco-lot-hunter.trycloudflare.com
https://tips-eco-lot-hunter.trycloudflare.com
https://tips-eco-lot-hunter.trycloudflare.com

--- people-temp-tunnel-christchurch ---
https://microphone-acquisition-ons-spine.trycloudflare.com
https://microphone-acquisition-ons-spine.trycloudflare.com
https://microphone-acquisition-ons-spine.trycloudflare.com
mainuser@PortainServer:~$
"""
        session = self.Session()
        try:
            device = models.Device(name="PortainServer", slug="portainserver", primary_ip="192.168.0.205")
            services = [
                models.Service(device=device, name="Kairix Temp Tunnel", slug="kairix-temp-tunnel"),
                models.Service(device=device, name="People Temp Tunnel Central", slug="people-temp-tunnel-central"),
                models.Service(device=device, name="People Temp Tunnel Dunedin", slug="people-temp-tunnel-dunedin"),
                models.Service(device=device, name="People Temp Tunnel Northern", slug="people-temp-tunnel-northern"),
                models.Service(device=device, name="People Temp Tunnel Christchurch", slug="people-temp-tunnel-christchurch"),
            ]
            session.add_all([device, *services])
            session.commit()

            parsed = parse_smart_paste(text)
            annotated = _annotate_import_suggestions(session, parsed)
            stored = _secure_parsed_for_storage(annotated)

            urls_by_source = {item["source_label"]: item for item in annotated["urls"]}
            self.assertNotIn("parse_warning", annotated)
            self.assertEqual(len(urls_by_source), 5)
            self.assertEqual(
                urls_by_source["kairix-temp-tunnel"]["url"],
                "https://involved-risks-roger-salad.trycloudflare.com",
            )
            self.assertEqual(
                urls_by_source["people-temp-tunnel-central"]["url"],
                "https://sparc-sustainable-bracket-eden.trycloudflare.com",
            )
            self.assertEqual(urls_by_source["people-temp-tunnel-central"]["history_urls"], ["https://sparc-sustainable-bracket-eden.trycloudflare.com"])
            self.assertEqual(urls_by_source["people-temp-tunnel-christchurch"]["suggested_service_id"], services[-1].id)
            self.assertEqual(stored["urls"][0]["url_type"], "public")
        finally:
            session.close()

    def test_inventory_with_captured_cloudflare_urls_does_not_repeat_lookup_helper(self) -> None:
        text = """=== HOST ===
 Static hostname: moxxie

=== IP ADDRESSES ===
eno1 UP 192.168.0.238/24

=== DOCKER CONTAINERS ===
NAMES                                     IMAGE                         STATUS      PORTS
temp-deputy-roster-view-url               cloudflare/cloudflared:latest Up 10 days
deputy-roster-view-deputy-roster-view-1   deputy-roster-view:local      Up 1 hour   0.0.0.0:8096->8000/tcp

=== DOCKER COMPOSE PROJECTS ===
NAME                 STATUS              CONFIG FILES
deputy-roster-view   running(1)          /data/compose/14/docker-compose.yml

=== CLOUDFLARE TUNNELS ===

--- temp-deputy-roster-view-url ---
https://bloggers-cst-segments-disposal.trycloudflare.com
"""
        parsed = parse_smart_paste(text)

        command_names = {item["name"] for item in parsed["commands"]}
        self.assertNotIn("Find temporary Cloudflare tunnel URLs", command_names)

    def test_inventory_with_cloudflared_container_without_urls_suggests_lookup_helper(self) -> None:
        text = """=== HOST ===
 Static hostname: moxxie

=== IP ADDRESSES ===
eno1 UP 192.168.0.238/24

=== DOCKER CONTAINERS ===
NAMES                       IMAGE                         STATUS      PORTS
temp-deputy-roster-view-url cloudflare/cloudflared:latest Up 10 days
"""
        parsed = parse_smart_paste(text)

        helper = next(item for item in parsed["commands"] if item["name"] == "Find temporary Cloudflare tunnel URLs")
        self.assertIn("temp-deputy-roster-view-url", helper["command_template"])

    def test_opsbook_stats_agent_uses_compose_project_name(self) -> None:
        text = """=== HOST ===
 Static hostname: moxxie

=== IP ADDRESSES ===
eno1 UP 192.168.0.238/24

=== DOCKER CONTAINERS ===
NAMES                 IMAGE                                  STATUS         PORTS
opsbook-stats-agent   ghcr.io/dubcodes/kairix-opsbook:latest Up 12 minutes

=== DOCKER COMPOSE PROJECTS ===
NAME            STATUS              CONFIG FILES
kairix-opsbook  running(2)          /data/compose/5/portainer-stack.yml
opsbook-agent   running(1)          /data/compose/18/docker-compose.yml
"""
        parsed = parse_smart_paste(text)
        service = next(item for item in parsed["services"] if item["name"] == "Opsbook Stats Agent")

        self.assertEqual(service["stack_group"], "opsbook-agent")
        self.assertEqual(service["compose_path"], "/data/compose/18/docker-compose.yml")

    def test_syncthing_relay_does_not_match_syncthing_service(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="PortainServer", slug="portainserver", primary_ip="192.168.0.205")
            syncthing = models.Service(
                device=device,
                name="Syncthing",
                slug="syncthing",
                local_url="http://192.168.0.205:1834/",
                container_name="syncthing",
                image="syncthing/syncthing:latest",
            )
            session.add_all(
                [
                    device,
                    syncthing,
                    models.Port(device=device, service=syncthing, host_port=22067, internal_port=22067),
                    models.Port(device=device, service=syncthing, host_port=22070, internal_port=22070),
                ]
            )
            session.commit()

            parsed = {
                "device": {"name": "PortainServer", "primary_ip": "192.168.0.205", "confidence": "medium"},
                "services": [
                    {
                        "name": "Syncthing Relay",
                        "container_name": "syncthing-relay",
                        "image": "syncthing/relaysrv:latest",
                        "stack_group": "syncthing",
                        "compose_path": "/data/compose/5/docker-compose.yml",
                        "confidence": "medium",
                        "urls": [
                            {"url": "http://192.168.0.205:22067/", "url_type": "local", "confidence": "medium"},
                            {"url": "http://192.168.0.205:22070/", "url_type": "local", "confidence": "medium"},
                        ],
                        "ports": [
                            {"host_port": 22067, "internal_port": 22067, "protocol": "tcp"},
                            {"host_port": 22070, "internal_port": 22070, "protocol": "tcp"},
                        ],
                        "credentials": [],
                    }
                ],
                "ports": [],
                "urls": [],
                "commands": [],
                "credentials": [],
                "tokens": [],
                "paths": [],
                "extras": {},
            }

            annotated = _annotate_import_suggestions(session, parsed)
            relay = annotated["services"][0]

            self.assertIsNone(relay["duplicate_id"])
            self.assertIn("New service", {badge["label"] for badge in relay["badges"]})
            self.assertFalse(any(badge["kind"] == "conflict" for badge in relay["badges"]))
        finally:
            session.close()

    def test_same_service_name_on_different_host_is_not_collapsed(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            old_host_service = models.Service(
                device=device,
                name="Kairix Graphics Builder",
                slug="kairix-graphics-builder",
                local_url="http://192.168.0.205:3010/controller",
                container_name="kairix-graphics-builder",
                image="ghcr.io/dubcodes/kairix-graphics-builder:latest",
            )
            session.add_all([device, old_host_service])
            session.commit()

            parsed = {
                "device": {"name": "moxxie", "primary_ip": "192.168.0.238", "confidence": "medium"},
                "services": [
                    {
                        "name": "Kairix Graphics Builder",
                        "container_name": "kairix-graphics-builder",
                        "image": "ghcr.io/dubcodes/kairix-graphics-builder:latest",
                        "stack_group": "kairix-graphics-builder",
                        "compose_path": "/data/compose/4/portainer-stack.yml",
                        "confidence": "medium",
                        "urls": [{"url": "http://192.168.0.238:3010/controller", "url_type": "local", "confidence": "medium"}],
                        "ports": [{"host_port": 3010, "internal_port": 3010, "protocol": "tcp"}],
                        "credentials": [],
                    }
                ],
                "ports": [],
                "urls": [],
                "commands": [],
                "credentials": [],
                "tokens": [],
                "paths": [],
                "extras": {},
            }

            annotated = _annotate_import_suggestions(session, parsed)
            service = annotated["services"][0]

            self.assertIsNone(service["duplicate_id"])
            self.assertIn("New service", {badge["label"] for badge in service["badges"]})
            self.assertFalse(any(detail.get("label") == "local URL" for detail in service.get("review_details", [])))
        finally:
            session.close()

    def test_stack_role_mismatch_does_not_match_app_to_db_service(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            db_service = models.Service(
                device=device,
                name="Kairix Opsbook Db",
                slug="kairix-opsbook-db",
                docker_project="kairix-opsbook",
                compose_path="/data/compose/5/portainer-stack.yml",
                container_name="kairix-opsbook-db",
                image="postgres:16-alpine",
            )
            session.add_all([device, db_service])
            session.commit()

            parsed = {
                "device": {"name": "moxxie", "primary_ip": "192.168.0.238", "confidence": "medium"},
                "services": [
                    {
                        "name": "Kairix Opsbook App",
                        "container_name": "kairix-opsbook-app",
                        "image": "ghcr.io/dubcodes/kairix-opsbook:latest",
                        "stack_group": "kairix-opsbook",
                        "compose_path": "/srv/storage/projects/kairix-opsbook/portainer-stack.yml",
                        "confidence": "medium",
                        "urls": [{"url": "http://192.168.0.238:8095/", "url_type": "local", "confidence": "medium"}],
                        "ports": [{"host_port": 8095, "internal_port": 8000, "protocol": "tcp"}],
                        "credentials": [],
                    }
                ],
                "ports": [],
                "urls": [],
                "commands": [],
                "credentials": [],
                "tokens": [],
                "paths": [],
                "extras": {},
            }

            annotated = _annotate_import_suggestions(session, parsed)
            service = annotated["services"][0]

            self.assertIsNone(service["duplicate_id"])
            self.assertIn("New service", {badge["label"] for badge in service["badges"]})
            self.assertFalse(any("container name" in badge["label"] for badge in service["badges"]))
        finally:
            session.close()

    def test_same_container_image_tag_change_is_update_not_conflict(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="Moxxie", slug="moxxie", primary_ip="192.168.0.238")
            service = models.Service(
                device=device,
                name="Kairix Opsbook",
                slug="kairix-opsbook",
                local_url="http://192.168.0.238:8095/",
                docker_project="kairix-opsbook",
                compose_path="/data/compose/5/portainer-stack.yml",
                container_name="kairix-opsbook-app",
                image="ghcr.io/dubcodes/kairix-opsbook:0.1.16",
            )
            session.add_all([device, service])
            session.commit()

            parsed = {
                "device": {"name": "moxxie", "primary_ip": "192.168.0.238", "confidence": "medium"},
                "services": [
                    {
                        "name": "Kairix Opsbook App",
                        "container_name": "kairix-opsbook-app",
                        "image": "ghcr.io/dubcodes/kairix-opsbook:latest",
                        "stack_group": "kairix-opsbook",
                        "compose_path": "/data/compose/5/portainer-stack.yml",
                        "confidence": "medium",
                        "urls": [{"url": "http://192.168.0.238:8095/", "url_type": "local", "confidence": "medium"}],
                        "ports": [{"host_port": 8095, "internal_port": 8000, "protocol": "tcp"}],
                        "credentials": [],
                    }
                ],
                "ports": [],
                "urls": [],
                "commands": [],
                "credentials": [],
                "tokens": [],
                "paths": [],
                "extras": {},
            }

            annotated = _annotate_import_suggestions(session, parsed)
            service_hint = annotated["services"][0]

            self.assertEqual(service_hint["duplicate_id"], service.id)
            self.assertIn("Updating entry: image", {badge["label"] for badge in service_hint["badges"]})
            self.assertFalse(any(badge["kind"] == "conflict" for badge in service_hint["badges"]))
            self.assertFalse(service_hint["review_details"])
        finally:
            session.close()

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
