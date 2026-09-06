import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("uvicorn.error")

def get_engine():
    db_url = settings.DATABASE_URL
    try:
        if db_url.startswith("sqlite"):
            engine = create_engine(
                db_url, 
                connect_args={"check_same_thread": False}
            )
        else:
            engine = create_engine(db_url, pool_pre_ping=True)
            # Test connection
            with engine.connect() as conn:
                pass
        return engine
    except Exception as e:
        logger.warning(
            f"Database connection to '{db_url}' failed ({e}). "
            f"Falling back to local SQLite database."
        )
        sqlite_fallback = f"sqlite:///{settings.BASE_DIR / 'network_attacks.db'}"
        return create_engine(
            sqlite_fallback, 
            connect_args={"check_same_thread": False}
        )

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app import models # register models with Base
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")
