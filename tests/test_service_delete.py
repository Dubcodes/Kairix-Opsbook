import unittest

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from kairix import models
from kairix.main import _delete_service_tree


class ServiceDeleteTreeTest(unittest.TestCase):
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

    def test_delete_service_tree_removes_url_references(self) -> None:
        session = self.Session()
        try:
            device = models.Device(name="PortainServer", slug="portainserver")
            service = models.Service(device=device, name="Temp Tunnel", slug="temp-tunnel")
            session.add_all([device, service])
            session.flush()

            credential = models.Credential(
                device_id=device.id,
                service_id=service.id,
                label="Temp login",
                secret_encrypted="encrypted",
            )
            port = models.Port(device_id=device.id, service_id=service.id, host_port=8090)
            url = models.Url(device_id=device.id, service_id=service.id, label="Temp", url="https://temp.example")
            command = models.Command(
                name="Temp command",
                category="Imported",
                applies_to_type="service",
                applies_to_id=service.id,
                command_template="echo ok",
            )
            session.add_all([credential, port, url, command])
            session.flush()

            tag = models.Tag(name="temp")
            recipe = models.Recipe(name="Linked recipe")
            recipe_step = models.RecipeStep(recipe=recipe, title="Run command", command_id=command.id)
            session.add(tag)
            session.flush()
            session.add_all(
                [
                    recipe,
                    recipe_step,
                    models.Note(object_type="service", object_id=service.id, title="Temp", body="Note"),
                    models.TagLink(object_type="service", object_id=service.id, tag_id=tag.id),
                    models.TagLink(object_type="credential", object_id=credential.id, tag_id=tag.id),
                    models.TagLink(object_type="port", object_id=port.id, tag_id=tag.id),
                    models.TagLink(object_type="url", object_id=url.id, tag_id=tag.id),
                    models.TagLink(object_type="command", object_id=command.id, tag_id=tag.id),
                ]
            )
            session.commit()
            service_id = service.id
            recipe_step_id = recipe_step.id

            _delete_service_tree(session, service)
            session.commit()

            self.assertEqual(session.query(models.Service).count(), 0)
            self.assertEqual(session.query(models.Url).filter_by(service_id=service_id).count(), 0)
            self.assertEqual(session.query(models.Port).filter_by(service_id=service_id).count(), 0)
            self.assertEqual(session.query(models.Credential).filter_by(service_id=service_id).count(), 0)
            self.assertEqual(session.query(models.Command).filter_by(applies_to_type="service", applies_to_id=service_id).count(), 0)
            self.assertIsNone(session.get(models.RecipeStep, recipe_step_id).command_id)
            self.assertEqual(session.query(models.TagLink).count(), 0)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
