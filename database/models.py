from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from .db_config import Base
from flask_login import UserMixin


class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    has_paid = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(50))
    threat_type = Column(String(255))
    severity = Column(String(20))
    source_tool = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)


class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True)
    description = Column(String(100))