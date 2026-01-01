from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
from core.models import AsyncSessionLocal, Subdomain, CrawledURL, Vulnerability, init_db

async def async_add_vulnerability(target_domain, name, severity, url, matcher_name=None, description=None):
    """Adds a discovered vulnerability to the database."""
    try:
        async with AsyncSessionLocal() as session:
            # Check duplicates (same vuln on same url)
            result = await session.execute(select(Vulnerability).filter_by(
                target_domain=target_domain,
                name=name,
                url=url,
                matcher_name=matcher_name
            ))
            existing = result.scalars().first()
            if existing:
                return False

            vuln = Vulnerability(
                target_domain=target_domain,
                name=name,
                severity=severity,
                url=url,
                matcher_name=matcher_name,
                description=description
            )
            session.add(vuln)
            await session.commit()
            return True
    except Exception as e:
        print(f"Error adding vulnerability: {e}")
        return False

async def get_async_session():
    """Returns a new async database session."""
    async with AsyncSessionLocal() as session:
        yield session

async def async_add_subdomain(target_domain, subdomain, source_tool):
    """
    Adds a new subdomain to the database asynchronously.
    Implements 'Insert Ignore' logic by checking for existence or handling IntegrityError.
    """
    async with AsyncSessionLocal() as session:
        try:
            # Check for existence
            # We use future style select
            result = await session.execute(select(Subdomain).filter_by(subdomain=subdomain))
            existing = result.scalars().first()
            
            if existing:
                return False

            new_sub = Subdomain(
                target_domain=target_domain,
                subdomain=subdomain,
                source_tool=source_tool
            )
            session.add(new_sub)
            await session.commit()
            return True
        except IntegrityError:
            await session.rollback()
            return False
        except Exception as e:
            await session.rollback()
            print(f"Error adding subdomain: {e}")
            return False

async def get_subdomains_for_target(target_domain):
    """Returns a list of subdomain strings for a given target."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Subdomain.subdomain).filter_by(target_domain=target_domain))
        return result.scalars().all()

async def update_subdomain_alive(subdomain_name, is_alive=True):
    """Updates the is_alive status of a subdomain."""
    async with AsyncSessionLocal() as session:
        try:
            # We assume subdomain_name matches what's in DB. 
            # httpx might return https://sub.com, we strip protocol if needed or store full url?
            # Model stores 'subdomain' (usually just hostname).
            # If input is url, strip it.
            hostname = subdomain_name.replace("https://", "").replace("http://", "").split("/")[0]
            
            result = await session.execute(select(Subdomain).filter_by(subdomain=hostname))
            sub = result.scalars().first()
            if sub:
                sub.is_alive = is_alive
                await session.commit()
                return True
            return False
        except Exception as e:
            await session.rollback()
            print(f"Error updating subdomain alive: {e}")
            return False

async def get_alive_subdomains_for_target(target_domain):
    """Returns a list of 'is_alive' subdomains for a given target."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Subdomain.subdomain).filter_by(target_domain=target_domain, is_alive=True))
        return result.scalars().all()

async def async_add_crawled_url(target_domain, url, source_tool, tags=None):
    """Adds a crawled URL to the DB, ignoring duplicates."""
    try:
        async with AsyncSessionLocal() as session:
            # Check if exists
            result = await session.execute(select(CrawledURL).filter_by(url=url))
            existing = result.scalars().first()
            if existing:
                # Optional: Update tags if new tags found?
                return False
            
            new_url = CrawledURL(
                target_domain=target_domain,
                url=url,
                source_tool=source_tool,
                tags=tags
            )
            session.add(new_url)
            await session.commit()
            return True
    except Exception as e:
        print(f"Error adding crawled URL: {e}")
        return False

async def get_all_crawled_urls(target_domain):
    """Returns a list of all crawled URLs for a target."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CrawledURL.url).filter_by(target_domain=target_domain))
        return result.scalars().all()

# Since init_db is async, we can't call it at module level easily without a loop.
# It should be called during app startup (FastAPI lifespan or main.py startup).
