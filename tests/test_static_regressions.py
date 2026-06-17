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

    def test_clickable_network_cards_open_endpoints_not_edit_by_default(self) -> None:
        root = Path(__file__).resolve().parents[1]
        templates_root = root / "app" / "templates"
        if not templates_root.exists():
            templates_root = root / "templates"

        for template_name in ["device_detail.html", "ports.html", "service_detail.html"]:
            with self.subTest(template=template_name):
                template = (templates_root / template_name).read_text()
                self.assertIn("port_open_url(port)", template)
                self.assertIn('data-card-target="_blank"', template)

    def test_clickable_card_supports_new_tab_targets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_js_path = root / "app" / "static" / "app.js"
        if not app_js_path.exists():
            app_js_path = root / "static" / "app.js"
        app_js = app_js_path.read_text()

        self.assertIn('data-card-target', app_js)
        self.assertIn('window.open(cardHref, "_blank", "noopener")', app_js)

    def test_smart_paste_preserves_existing_device_name_casing(self) -> None:
        root = Path(__file__).resolve().parents[1]
        main_py_path = root / "app" / "kairix" / "main.py"
        if not main_py_path.exists():
            main_py_path = root / "kairix" / "main.py"
        main_py = main_py_path.read_text()

        self.assertIn("new_device_name.lower() != device.name.lower()", main_py)

    def test_token_generator_uses_session_storage_not_query_string(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_js_path = root / "app" / "static" / "app.js"
        tokens_path = root / "app" / "templates" / "tokens.html"
        credential_form_path = root / "app" / "templates" / "credential_form.html"
        if not app_js_path.exists():
            app_js_path = root / "static" / "app.js"
            tokens_path = root / "templates" / "tokens.html"
            credential_form_path = root / "templates" / "credential_form.html"

        app_js = app_js_path.read_text()
        tokens_template = tokens_path.read_text()
        credential_form = credential_form_path.read_text()

        self.assertIn("opsbook-generated-token", app_js)
        self.assertIn("sessionStorage.setItem", app_js)
        self.assertIn("tokenGeneratorOpen", app_js)
        self.assertIn("data-token-generator-modal", tokens_template)
        self.assertIn("data-credential-secret-input", credential_form)

    def test_static_assets_are_versioned_for_browser_cache_busting(self) -> None:
        root = Path(__file__).resolve().parents[1]
        base_path = root / "app" / "templates" / "base.html"
        if not base_path.exists():
            base_path = root / "templates" / "base.html"
        base_template = base_path.read_text()

        self.assertIn("/static/app.js?v={{ settings.app_version|urlencode }}", base_template)
        self.assertIn("/static/styles.css?v={{ settings.app_version|urlencode }}", base_template)


if __name__ == "__main__":
    unittest.main()
