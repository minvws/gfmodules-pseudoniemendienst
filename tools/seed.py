from app.db.entities.authorization import Authorization
import uuid
from uuid import UUID
from app.db.entities.hsm_key_versions import HsmKeyVersion
import datetime
from sqlalchemy import text, exists, select, func
from app.config import get_config
from app.db.db import Database

if __name__ == "__main__":
    print("Seeding database")
    config = get_config()
    db = Database(config.database.dsn)
    oin = "00000003123456780000"
    organization_id = uuid.UUID("daff00e0-559e-4939-82b2-8f53efe33f35")
    with db.get_db_session() as session:
        session.execute(
            text(
                f"insert into admin.organizations (id, external_id, name, created_at) values ('{organization_id}', '{oin}', 'seeded org', '{datetime.datetime.now()}')"
            )
        )
        session.add(
            HsmKeyVersion(
                organization_id=organization_id,
                version=1,
                from_dt=datetime.datetime.now(),
            )
        )
        session.commit()
