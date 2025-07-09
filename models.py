from sqlalchemy import Column, String, LargeBinary, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
Base = declarative_base()

class ThreatHash(Base):
    __tablename__ = 'threat_hashes'
    hash_prefix = Column(LargeBinary(4), primary_key=True)
    full_hash = Column(LargeBinary(32), primary_key=True)
    threat_type = Column(String, primary_key=True)

    def __repr__(self):
        return (f"<ThreatHash(prefix={self.hash_prefix.hex()}, "
                f"full_hash={self.full_hash.hex()}, type='{self.threat_type}')>")

class ListMetadata(Base):
    __tablename__ = 'list_metadata'
    list_name = Column(String, primary_key=True)
    version_token = Column(LargeBinary, nullable=True)
    last_updated_at = Column(DateTime, default=func.now())
    recommended_next_update_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return (f"<ListMetadata(name='{self.list_name}', "
                f"version='{self.version_token.hex() if self.version_token else 'None'}', " # type: ignore
                f"last_updated={self.last_updated_at}, "
                f"next_update={self.recommended_next_update_at})>")
