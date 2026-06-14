import unittest
from pathlib import Path


class StaticRegressionTest(unittest.TestCase):
    def test_favorite_form_ajax_includes_clicked_submit_button(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_js_path = root / "app" / "static" / "app.js"
        if not app_js_path.exists():
            app_js_path = root / "static" / "app.js"
        app_js = app_js_path.read_text()

        self.assertIn("const submitter = event.submitter", app_js)
        self.assertIn("formData.append(submitter.name, submitter.value)", app_js)
        self.assertIn('favoriteForm.getAttribute("action")', app_js)


if __name__ == "__main__":
    unittest.main()
