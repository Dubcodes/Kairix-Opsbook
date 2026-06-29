import os
from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
if not (Path.cwd() / "static").exists() and (APP_ROOT / "static").exists():
    os.chdir(APP_ROOT)

from kairix.main import app


class RouteIntegrityTest(unittest.TestCase):
    @staticmethod
    def _has_route(path: str, method: str) -> bool:
        for route in app.routes:
            methods = getattr(route, "methods", None)
            path_regex = getattr(route, "path_regex", None)
            if not methods or path_regex is None or method not in methods:
                continue
            if path_regex.fullmatch(path):
                return True
        return False

    def test_literal_template_links_and_forms_have_routes(self) -> None:
        templates_dir = APP_ROOT / "templates"
        missing: list[str] = []

        for template_path in templates_dir.rglob("*.html"):
            source = template_path.read_text(encoding="utf-8")
            relative = template_path.relative_to(templates_dir)

            for match in re.finditer(r'<a\b[^>]*\bhref="([^"]+)"', source, re.IGNORECASE):
                value = match.group(1)
                if not value.startswith("/"):
                    continue
                path = urlsplit(value).path
                if "{{" in path or "{%" in path or path.startswith("/static/"):
                    continue
                if not self._has_route(path, "GET"):
                    missing.append(f"{relative}: GET {path}")

            for match in re.finditer(r'<form\b[^>]*>', source, re.IGNORECASE):
                tag = match.group(0)
                action_match = re.search(r'\baction="([^"]+)"', tag, re.IGNORECASE)
                if not action_match:
                    continue
                value = action_match.group(1)
                if not value.startswith("/"):
                    continue
                path = urlsplit(value).path
                if "{{" in path or "{%" in path:
                    continue
                method_match = re.search(r'\bmethod="([^"]+)"', tag, re.IGNORECASE)
                method = (method_match.group(1) if method_match else "GET").upper()
                if not self._has_route(path, method):
                    missing.append(f"{relative}: {method} {path}")

        self.assertEqual(missing, [], "Literal template routes without matching endpoints:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
