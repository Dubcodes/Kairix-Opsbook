import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


class TemplateSyntaxTest(unittest.TestCase):
    def test_all_templates_compile(self) -> None:
        templates_dir = Path(__file__).resolve().parents[1] / "app" / "templates"
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        env.filters.update({"dt": str, "date_input": str, "urlencode": str, "stat_percent": str, "stat_bytes": str, "stat_duration": str})

        for template_path in templates_dir.rglob("*.html"):
            name = str(template_path.relative_to(templates_dir)).replace("\\", "/")
            with self.subTest(template=name):
                env.get_template(name)


if __name__ == "__main__":
    unittest.main()
