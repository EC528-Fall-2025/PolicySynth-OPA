from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

def get_engine(db_url: str):
    return create_engine(db_url, echo=False, future=True)

def get_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)

def init_db(db_url: str):
    engine = get_engine(db_url)
    Base.metadata.create_all(engine)
    return get_session_factory(engine)