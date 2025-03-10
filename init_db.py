from src.database.models import Base; from src.database import engine; Base.metadata.create_all(bind=engine)
