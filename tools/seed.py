from datetime import datetime, timezone
from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.enums.personal_id_type import PersonalIdType
from app.models.oin import Oin
from app.db.models import OrganizationEntity, HsmKeyVersionEntity
from app.config import get_config
from app.db.db import Database

if __name__ == "__main__":
    print("Seeding database")
    config = get_config()
    db = Database(config.database)
    oin = "00000003123456780000"
    with db.get_db_session() as db_session:
        org = (
            db_session.session.query(OrganizationEntity)
            .filter(OrganizationEntity.external_id == oin)
            .first()
        )
        if not org:
            personal_ids = (
                db_session.session.query(PersonalIdTypeEntity)
                .filter(PersonalIdTypeEntity.name == PersonalIdType.OPRF)
                .all()
            )
            org = OrganizationEntity(
                external_id=Oin(oin),
                name="test_org",
                receive_personal_id_types=list(personal_ids),
                request_personal_id_types=list(personal_ids),
                hsm_key_versions=[
                    HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
                ],
            )
            db_session.add(org)
            db_session.commit()
