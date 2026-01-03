import os
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Define the base class for models
Base = declarative_base()

class Subdomain(Base):
    """
    Model representing a discovered subdomain.
    """
    __tablename__ = 'subdomains'

    id = Column(Integer, primary_key=True)
    target_domain = Column(String, nullable=False)
    subdomain = Column(String, unique=True, nullable=False)
    source_tool = Column(String, nullable=True)
    is_alive = Column(Boolean, default=False)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Subdomain(subdomain='{self.subdomain}', is_alive={self.is_alive})>"

class CrawledURL(Base):
    __tablename__ = 'crawled_urls'
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    target_domain = Column(String, index=True)
    source_tool = Column(String)
    tags = Column(String, nullable=True) # JSON or comma-sep strings: "xss,sqli"
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

class Vulnerability(Base):
    """
    Model representing a discovered vulnerability (Nuclei result).
    """
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    target_domain = Column(String, index=True)
    name = Column(String)
    severity = Column(String) # info, low, medium, high, critical
    url = Column(String)
    matcher_name = Column(String, nullable=True)
    description = Column(String, nullable=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

class FuzzingResult(Base):
    """
    Model representing a directory/file discovered via FFUF.
    """
    __tablename__ = 'fuzzing_results'

    id = Column(Integer, primary_key=True)
    target_domain = Column(String, index=True)
    url = Column(String, unique=True, index=True)
    status_code = Column(Integer)
    content_length = Column(Integer)
    preset_used = Column(String, nullable=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

class Configuration(Base):
    """
    Dynamic Configuration Store.
    Key Examples: "global:phase:subdomain", "tool:subfinder:flags"
    """
    __tablename__ = 'configurations'

    key = Column(String, primary_key=True, index=True)
    value = Column(Text, nullable=False) # JSON encoded string
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# Database Setup
# Use DATABASE_URL from env, default to SQLite for backward compat
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./recon.db")

# Async Engine
# echo=False for production/performance
engine = create_async_engine(DATABASE_URL, echo=False)

# Async Session Factory
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

async def init_db():
    """Initializes the database tables asynchronously."""
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all) # Optional: Reset DB
        await conn.run_sync(Base.metadata.create_all)
