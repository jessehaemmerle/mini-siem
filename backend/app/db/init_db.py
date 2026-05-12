from app.db.base import Base
from app.db.session import engine
from app.models import *  # noqa: F401,F403
from app.services.opensearch_service import create_index_template


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    create_index_template()


if __name__ == "__main__":
    init_db()
