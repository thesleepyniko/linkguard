import asyncio
import logging
import os
import re
import urllib.parse as urllib_parse
from datetime import datetime, timedelta
import hashlib
import ipaddress

from dotenv import load_dotenv
from google.cloud import webrisk_v1
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from models import Base, ListMetadata, ThreatHash

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
webrisk_manager_instance = None

class WebRiskAPICaller:
    DB_NAME = 'webrisk.db'
    THREAT_TYPES_ENUM = [
        webrisk_v1.ThreatType.MALWARE,
        webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
        webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
        webrisk_v1.ThreatType.SOCIAL_ENGINEERING_EXTENDED_COVERAGE
    ]
    DEFAULT_MIN_UPDATE_INTERVAL_SECONDS = 30 * 60 
    FORCE_API_ON_MISS = False

    def __init__(self):
        self.engine = create_engine(
            f'sqlite:///{self.DB_NAME}',
            connect_args={
                'check_same_thread': False,
                'timeout': 30
            },
            pool_pre_ping=True,
            echo=False) 
        with self.engine.connect() as conn: # increase some performance cuz we need large writes
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA synchronous=NORMAL") 
            conn.exec_driver_sql("PRAGMA cache_size=10000")
            conn.exec_driver_sql("PRAGMA temp_store=memory")
            conn.commit()
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.client = webrisk_v1.WebRiskServiceAsyncClient()
        self.has_removals = False
        asyncio.create_task(self.update_threat_lists())

    
    async def _get_threat_list_metadata(self, session: Session, threat_list: str):
        return session.query(ListMetadata).filter(ListMetadata.list_name == threat_list.upper()).first()


    async def _save_threat_list_metadata(self, session: Session, threat_list: str, version_token: bytes, next_update_at):
        metadata = session.query(ListMetadata).filter(ListMetadata.list_name == threat_list.upper()).first()
        if not metadata:
            new_metadata = ListMetadata(
                list_name=threat_list.upper(), 
                version_token=version_token,
                last_updated_at=datetime.now(),
                recommended_next_update_at=next_update_at
            )
            session.add(new_metadata)
            return
        metadata.version_token = version_token # type: ignore
        metadata.last_updated_at = datetime.now() # type: ignore
        metadata.recommended_next_update_at = next_update_at
        return
    
    #hoping and praying that this will work
    async def _handle_reset_response(self, session: Session, list_name: str, additions: webrisk_v1.ThreatEntryAdditions):
        session.query(ThreatHash).filter(ThreatHash.threat_type == list_name.upper()).delete(synchronize_session="fetch") # a RST response indicates we must wipe our db and repopulate
        hashes_count = 0
        objects=[]
        for raw_hashes_obj in additions.raw_hashes:
            prefix_size = raw_hashes_obj.prefix_size
            concatenated_hashes_bytes = raw_hashes_obj.raw_hashes
            for i in range(0, len(concatenated_hashes_bytes), prefix_size):
                individual_hash_bytes = concatenated_hashes_bytes[i:i+prefix_size]

                db_hash_prefix = individual_hash_bytes                     # <- exact size
                db_full_hash = individual_hash_bytes if len(individual_hash_bytes) == 32 else None

                objects.append(ThreatHash(
                    threat_type=list_name.upper(),
                    hash_prefix=db_hash_prefix,
                    prefix_size=prefix_size,
                    full_hash=db_full_hash
                ))
                hashes_count += 1
        session.bulk_save_objects(objects, return_defaults=False)
        logger.info(msg=f"Added {hashes_count} to DB while handling RESET response for {list_name}")
        return
    
    async def _handle_diff_response(self, session: Session, list_name: str, additions: webrisk_v1.ThreatEntryAdditions, removals: webrisk_v1.ThreatEntryRemovals):
        hashes_added = 0
        objects=[]
        if additions and additions.raw_hashes:
            for raw_hashes_obj in additions.raw_hashes:
                prefix_size = raw_hashes_obj.prefix_size
                concatenated_hashes_bytes = raw_hashes_obj.raw_hashes
                for i in range(0, len(concatenated_hashes_bytes), prefix_size):
                    individual_hash_bytes = concatenated_hashes_bytes[i:i+prefix_size]

                    db_hash_prefix = individual_hash_bytes                     # <- exact size
                    db_full_hash = individual_hash_bytes if len(individual_hash_bytes) == 32 else None

                    objects.append(ThreatHash(
                        threat_type=list_name.upper(),
                        hash_prefix=db_hash_prefix,
                        prefix_size=prefix_size,
                        full_hash=db_full_hash
                     ))
                    hashes_added +=1
        logger.info(msg=f"Added {hashes_added} to DB while handling RESET response for {list_name}")
        session.bulk_save_objects(objects, return_defaults=False)
        await self._save_threat_list_metadata(session, list_name, b"", "")
        if removals and removals.raw_indices:
            # this is just not prod ready in any way whatsoever but whatever
            logger.warning("Got DIFF with removals, preparing DB to RESET next cycle")
            self.has_removals = True
        logger.info(f"DIFF response for {list_name}: +{hashes_added} hashes")

    async def update_threat_lists(self):
        with self.Session() as session:
            for threat_type in self.THREAT_TYPES_ENUM:
                try:
                    metadata = await self._get_threat_list_metadata(session, threat_type.name)
                    req_constraints = webrisk_v1.ComputeThreatListDiffRequest.Constraints()
                    req_constraints.max_diff_entries = 1000000
                    req_constraints.max_database_entries = 1000000
                    request = webrisk_v1.ComputeThreatListDiffRequest(
                        threat_type=threat_type,
                        constraints=req_constraints,
                    )
                    if not metadata:
                        request = webrisk_v1.ComputeThreatListDiffRequest(
                                    threat_type=threat_type,
                                    constraints=req_constraints,
                                )
                        response = await self.client.compute_threat_list_diff(request=request)
                        if response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.RESET:
                                    logger.info(f"Handling RESET response for {threat_type.name}")
                                    await self._handle_reset_response(session, threat_type.name, response.additions)
                        elif response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.DIFF:
                            logger.info(f"Handling DIFF response for {threat_type.name}")
                            await self._handle_diff_response(session, threat_type.name, response.additions, response.removals)
                        await self._save_threat_list_metadata(
                                session, 
                                threat_type.name, 
                                response.new_version_token, 
                                response.recommended_next_diff
                            )
                        session.commit()
                        logger.info(f"updated {threat_type.name}! :D")
                    elif metadata.recommended_next_update_at: #type: ignore
                        if datetime.now() >= metadata.recommended_next_update_at: #type: ignore
                            if metadata and metadata.version_token: #type: ignore
                                request.version_token = metadata.version_token #type: ignore
                                logger.info(f"current version token: {threat_type.name}")
                                response = await self.client.compute_threat_list_diff(request=request, version_token=metadata.version_token) #type: ignore
                            else:
                                logger.info(f"no version token for {threat_type.name}, manually triggering a reset")
                                request = webrisk_v1.ComputeThreatListDiffRequest(
                                    threat_type=threat_type,
                                    constraints=req_constraints,
                                )
                                response = await self.client.compute_threat_list_diff(request=request)
                            if response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.RESET:
                                    logger.info(f"Handling RESET response for {threat_type.name}")
                                    await self._handle_reset_response(session, threat_type.name, response.additions)
                            elif response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.DIFF:
                                logger.info(f"Handling DIFF response for {threat_type.name}")
                                await self._handle_diff_response(session, threat_type.name, response.additions, response.removals)

                            await self._save_threat_list_metadata(
                                    session, 
                                    threat_type.name, 
                                    response.new_version_token, 
                                    response.recommended_next_diff
                                )
                            session.commit()
                            logger.info(f"updated {threat_type.name}! :D")
                        else:
                            logger.info(f"didn't need to update {threat_type.name}! next updated scheduled for {metadata.recommended_next_update_at}")

                except Exception as e:
                    logger.error(f"uh oh! something went wrong updating {threat_type.name}: {e}")
                    session.rollback()
                    continue

    def _normalize_ipv6(self, ip_str: str) -> str | None:
        try:
            ip_obj = ipaddress.IPv6Address(ip_str)
            return ip_obj.exploded
        except ipaddress.AddressValueError:
            return None

    def _normalize_ipv4(self, ip_str: str) -> str | None:
        try:
            if any(part.startswith('0') and len(part) > 1 for part in ip_str.split('.')):
                return None
            ip_obj = ipaddress.IPv4Address(ip_str)
            return str(ip_obj)
        except (ipaddress.AddressValueError, ValueError):
            return None

    def _canonicalize_url(self, url: str) -> str:
        try:
            url = url.strip().replace('\t', '').replace('\r', '').replace('\n', '')
            url = url.split('#', 1)[0]

            while True:
                new_url = urllib_parse.unquote(url)
                if new_url == url:
                    break
                url = new_url

            parsed = urllib_parse.urlparse(url)
            if not parsed.scheme:
                parsed = urllib_parse.urlparse('http://' + url)

            host = parsed.hostname
            if not host:
                return url

            normalized_ip = self._normalize_ipv6(host) or self._normalize_ipv4(host)
            if normalized_ip:
                host = normalized_ip
            else:
                host = host.lower().strip('.')
                host = re.sub(r'\.+', '.', host)

            path = parsed.path or '/'
            path = re.sub(r'/./', '/', path)
            path = re.sub(r'//+', '/', path)

            path_segments = path.split('/')
            new_segments = []
            for segment in path_segments:
                if segment == '..':
                    if len(new_segments) > 1:
                        new_segments.pop()
                else:
                    new_segments.append(segment)
            path = '/'.join(new_segments)
            if not path.startswith('/'):
                path = '/' + path

            canonical_url = host + path
            if parsed.query:
                canonical_url += '?' + parsed.query
            
            return canonical_url

        except Exception as e:
            logger.warning(f"couldnt canonicalize {url}: {e}")
            return url
        
    def _host_candidates_from_host(self, host: str) -> list[str]:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) or ':' in host:
            return [host]
        
        labels = host.split('.')
        candidates = []
        if len(labels) > 4:
             labels = labels[-4:]

        for i in range(len(labels)):
            candidate = '.'.join(labels[i:])
            if candidate:
                candidates.append(candidate)
        
        if host not in candidates:
            candidates.append(host)

        return list(dict.fromkeys(candidates))


    def _path_candidates_from_path_query(self, path: str, query: str) -> list[str]:
        candidates = []
        if path:
            candidates.append(path)
            path_segments = path.split('/')
            if len(path_segments) > 1:
                for i in range(4, 0, -1):
                    if len(path_segments) > i:
                        candidate_path = '/'.join(path_segments[:i])
                        if candidate_path and candidate_path not in candidates:
                            candidates.append(candidate_path)
        
        candidates.append('/')

        path_with_query_candidates = []
        for p in candidates:
            path_with_query_candidates.append(p)
            if query:
                path_with_query_candidates.append(f"{p}?{query}")

        return list(dict.fromkeys(path_with_query_candidates))


    def _get_url_expressions(self, canonical_url: str) -> list[str]:
        parsed = urllib_parse.urlparse('http://' + canonical_url)
        host_candidates = self._host_candidates_from_host(parsed.hostname or '')
        path_candidates = self._path_candidates_from_path_query(parsed.path, parsed.query)
        
        expressions = []
        for host_candidate in host_candidates:
            for path_candidate in path_candidates:
                expressions.append(host_candidate + path_candidate)
        logger.info(f"Generated {len(expressions)} expressions for {canonical_url}")
        return expressions

    def _compute_url_hashes(self, url: str):
        canonical_url = self._canonicalize_url(url)
        expressions = self._get_url_expressions(canonical_url)
        
        hashes = set()
        for expr in expressions:
            full_hash = hashlib.sha256(expr.encode('utf-8')).digest()
            hashes.add(full_hash)
        logger.info(f"Computed {len(hashes)} hashes for {url}")
        return hashes
    
    async def check_url_safety(self, url: str):
        hashes = self._compute_url_hashes(url)
        prefixes = {h[:4] for h in hashes}
        logger.info(f"Checking {len(prefixes)} prefixes against local DB.")

        with self.Session() as session:
            for prefix in prefixes:
                threat = session.query(ThreatHash).filter(ThreatHash.hash_prefix == prefix).first()
                if threat:
                    logger.info(f"Prefix match found in DB: {prefix.hex()}")
                    for full_hash in hashes:
                        if full_hash.startswith(prefix):
                            if threat.full_hash is not None and threat.full_hash == full_hash:
                                logger.info(f"Full hash match found for {prefix.hex()}. Threat confirmed.")
                                return {
                                    'is_threat': True,
                                    'threat_type': threat.threat_type,
                                    'url': url,
                                    'match_type': 'full_hash_local'
                                }
                    
                    logger.info(f"Prefix {prefix.hex()} matched, but no full hash match. Verifying with API.")
                    api_result = await self._verify_threat_with_api(url)
                    if api_result.get('is_threat'):
                        api_result['match_type'] = 'api_verification_after_prefix_hit'
                        return api_result

        logger.info("No threat found in local DB.")
        if self.FORCE_API_ON_MISS:
            logger.info("Forcing API check on local miss.")
            return await self._verify_threat_with_api(url)

        return {"is_threat": False, "url": url, "match_type": "none"}


    async def _verify_threat_with_api(self, url: str):
        """Verify threat status directly with Web Risk API"""
        try:
            request = webrisk_v1.SearchUrisRequest(
                uri=url,
                threat_types=self.THREAT_TYPES_ENUM
            )
            
            response = await self.client.search_uris(request=request)
            
            if response.threat:
                return {
                    'is_threat': True,
                    'threat_types': [threat_type.name for threat_type in response.threat.threat_types],
                    'url': url,
                    'match_type': 'api_verification'
                }
            else:
                return {
                    'is_threat': False,
                    'url': url,
                    'match_type': 'api_verification'
                }
                
        except Exception as e:
            logger.error(f"Error verifying URL with API: {e}")
            return {
                'is_threat': False,
                'url': url,
                'match_type': 'api_error',
                'error': str(e)
            }
# Initializes your app with your bot token
app = AsyncApp(token=os.environ.get("SLACK_BOT_TOKEN"))

def check_for_urls(element, data=None):
    if data is None:
        data = set()
    logger.info(element)
    if isinstance(element, list):
        for element_iter in element:
            logger.info(f"checking lay1: {element_iter}")
            if element_iter.get('type', '') == "link":
                logger.info(f"found link, link is {element_iter.get('url', '')}")
                data.add(element_iter.get('url', ''))
            else:
                logger.info("failed check, recursing")
                check_for_urls(element_iter, data)
    elif isinstance(element, dict):
        logger.info(f"evaluating {element} as dict")
        if element.get("type", "") == "rich_text" or element.get("type", "") == "rich_text_section":
            check_for_urls(element.get('elements'), data)
        elif element.get("type", "") == "rich_text_list":
            check_for_urls(element.get("items"), data)
    return list(data)
        

# Listens to incoming messages that contain "hello"
@app.message(".*")
async def handle_messages(message, say):
    if not webrisk_manager_instance:
        logger.error("WebRiskAPICaller not initialized, skipping message.")
        return

    text = message.get("text", "")
    if "http" not in text:
        return 
    links=check_for_urls(message.get('blocks', []))

    for link in links:
        result = await webrisk_manager_instance.check_url_safety(link)
        logger.info(result)
        if result.get('is_threat', False):
            await say(
                blocks=[
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"Hey there <@{message['user']}>! I flagged {result.get('url')} under the category {result.get('threat_types')} in your message! Please exercise caution when clicking said link!"},

                    }
                ],
                text=f"Hey there <@{message['user']}>!",
            )

async def main():
    global webrisk_manager_instance
    logger.info("Initalizing app.")
    logging.getLogger("slack_sdk").setLevel(logging.DEBUG)
    webrisk_manager_instance = WebRiskAPICaller()
    logger.info("WebRiskAPICaller intialized")
    handler = AsyncSocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    await handler.start_async()

# Start your app
if __name__ == "__main__":
    asyncio.run(main())