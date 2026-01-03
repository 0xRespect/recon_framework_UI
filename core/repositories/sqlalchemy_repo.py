from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from core.models import Subdomain, CrawledURL, Vulnerability
from .base import IRepository
import os

# Get DB URL from env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./recon.db")

class SqlAlchemyRepository(IRepository):
    """
    SQLAlchemy implementation optimized for PostgreSQL (asyncpg) with Connection Pooling.
    """
    
    def __init__(self, db_url=None):
        self.db_url = db_url or DATABASE_URL
        # Create Async Engine with pooling
        self.engine = create_async_engine(
            self.db_url,
            echo=False,
            pool_size=20,          # Support high concurrency
            max_overflow=10,
            pool_pre_ping=True
        )
        self.session_factory = sessionmaker(
            self.engine, 
            expire_on_commit=False, 
            class_=AsyncSession
        )

    async def add_subdomain(self, target_domain: str, subdomain: str, source_tool: str) -> bool:
        async with self.session_factory() as session:
            try:
                # Check existence
                result = await session.execute(select(Subdomain).filter_by(subdomain=subdomain))
                existing = result.scalars().first()
                if existing:
                    return False
                
                new_sub = Subdomain(target_domain=target_domain, subdomain=subdomain, source_tool=source_tool)
                session.add(new_sub)
                await session.commit()
                return True
            except IntegrityError:
                await session.rollback()
                return False
            except Exception as e:
                # Log error
                # print(f"DB Error: {e}")
                await session.rollback()
                return False
                await session.rollback()
                return False

    async def get_subdomains(self, target_domain: str) -> List[str]:
        async with self.session_factory() as session:
            result = await session.execute(select(Subdomain.subdomain).filter_by(target_domain=target_domain))
            return result.scalars().all()

    async def get_alive_subdomains(self, target_domain: str) -> List[str]:
        async with self.session_factory() as session:
             result = await session.execute(select(Subdomain.subdomain).filter_by(target_domain=target_domain, is_alive=True))
             return result.scalars().all()

    async def update_subdomain_alive(self, subdomain: str, is_alive: bool) -> bool:
        async with self.session_factory() as session:
            # logic to handle url vs hostname
            hostname = subdomain.replace("https://", "").replace("http://", "").split("/")[0]
            result = await session.execute(select(Subdomain).filter_by(subdomain=hostname))
            sub = result.scalars().first()
            if sub:
                sub.is_alive = is_alive
                await session.commit()
                return True
            return False

    async def add_crawled_url(self, target_domain: str, url: str, source: str, tags: str = None) -> bool:
        async with self.session_factory() as session:
             try:
                result = await session.execute(select(CrawledURL).filter_by(url=url))
                if result.scalars().first():
                    return False
                
                new_url = CrawledURL(target_domain=target_domain, url=url, source_tool=source, tags=tags)
                session.add(new_url)
                await session.commit()
                return True
             except:
                 await session.rollback()
                 return False

    async def get_crawled_urls(self, target_domain: str) -> List[str]:
        async with self.session_factory() as session:
            result = await session.execute(select(CrawledURL.url).filter_by(target_domain=target_domain))
            return result.scalars().all()

    async def add_vulnerability(self, target_domain: str, name: str, severity: str, url: str, matcher: str = None, description: str = None) -> bool:
        async with self.session_factory() as session:
            try:
                result = await session.execute(select(Vulnerability).filter_by(target_domain=target_domain, name=name, url=url, matcher_name=matcher))
                if result.scalars().first():
                    return False
                
                vuln = Vulnerability(
                    target_domain=target_domain, name=name, severity=severity, 
                    url=url, matcher_name=matcher, description=description
                )
                session.add(vuln)
                await session.commit()
                return True
            except:
                await session.rollback()
                return False
