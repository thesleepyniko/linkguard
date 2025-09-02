import asyncio
import logging
import os
import re
import urllib.parse as urllib_parse
from datetime import datetime, timedelta
import hashlib

from dotenv import load_dotenv
from google.cloud import webrisk_v1
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from models import Base, ListMetadata, ThreatHash

# This sample slack application uses SocketMode
# For the companion getting started setup guide, 
# see: https://slack.dev/bolt-python/tutorial/getting-started 

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
webrisk_manager_instance = None # intialize first

# URL_PATTERN = re.compile(r"""
#     (?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@
#     )))
# """, re.IGNORECASE | re.VERBOSE) # yea this is pretty long, sorry...

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
                individual_hash_bytes = concatenated_hashes_bytes[i : i + prefix_size]

                db_hash_prefix = individual_hash_bytes[:4] # should always be 4 bytes
                db_full_hash = None

                if len(individual_hash_bytes) == 32:
                    db_full_hash = individual_hash_bytes

                objects.append(ThreatHash(
                    threat_type=list_name.upper(),
                    hash_prefix=db_hash_prefix,
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
                    db_hash_prefix = individual_hash_bytes[:4]
                    db_full_hash = None
                    if len(individual_hash_bytes) == 32:
                        db_full_hash = individual_hash_bytes
                    objects.append(ThreatHash(
                        threat_type=list_name.upper(),
                        hash_prefix=db_hash_prefix,
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
                    req_constraints.max_diff_entries = 16777216
                    req_constraints.max_database_entries = 16777216
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

    def _canonicalize_url(self, url: str) -> str:
        try:
            parsed = urllib_parse.urlparse(url.lower().strip())
            
            scheme = parsed.scheme or 'http'
            netloc = parsed.netloc
            path = parsed.path or '/'
            
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')
            
            if path != '/' and path.endswith('/'):
                path = path.rstrip('/')
            
            canonicalized = f"{scheme}://{netloc}{path}"
            if parsed.query:
                canonicalized += f"?{parsed.query}"
            
            logger.info(f"canonicalized {url} into {canonicalized}")
            return canonicalized
        
        except Exception as e:
            logger.warning(f"couldnt canonicalize {url}: {e}")
            return url
        
    def _compute_url_hashes(self, url: str):
        canonical_url = self._canonicalize_url(url)
        
        # calculate the hash of the canonical url
        full_hash = hashlib.sha256(canonical_url.encode('utf-8')).digest()
        
        # try some different lengths
        prefixes = []
        for length in [4, 8, 16, 32]:
            if length <= len(full_hash):
                prefixes.append(full_hash[:length])
        
        return prefixes, full_hash
    async def check_url_safety(self, url: str):
        prefixes, full_hash = self._compute_url_hashes(url)
        
        with self.Session() as session:
            for prefix in prefixes:
                threat = session.query(ThreatHash).filter(
                    ThreatHash.hash_prefix == prefix[:4]
                ).first()
                
                if threat:
                    if threat.full_hash and threat.full_hash == full_hash: # type: ignore
                        return {
                            'is_threat': True,
                            'threat_type': threat.threat_type,
                            'url': url,
                            'match_type': 'full_hash'
                        } # we found a threat and it had a full hash! lets return some info
                    elif threat.full_hash is None:
                        return await self._verify_threat_with_api(url) # we didn't find a threat let's talk to google to find out if its a threat :3
        if self.FORCE_API_ON_MISS:
            return await self._verify_threat_with_api(url)
        else:
            return {"is_threat": False, "url": url, "match_type": "none"} # indicates that there were no threats found, so it should technically be good

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
    text = message.get("text", "")
    #logger.info(message)
    if "http" not in text:
        return 
    links=check_for_urls(message.get('blocks', []))
    #if "." not in text:
    #    return
    #else:
    #    ret = match_for_url(text)
    #    if not ret:
    #        return
    # say() sends a message to the channel where the event was triggered
    for link in links:
        result = await WebRiskAPICaller().check_url_safety(link)
        logger.info(result)
        if result.get('is_threat', False):
            await say(
                blocks=[
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"Hey there <@{message['user']}>! Your message was {text}. I found the following links: {links}. I flagged {result.get('url')} under the category {result.get('threat_types')}"},
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Click Me"},
                            "action_id": "button_click",
                        },
                    }
                ],
                text=f"Hey there <@{message['user']}>!",
            )
        else:
            await say(
                blocks=[
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"Hey there <@{message['user']}>! Your message was {text}. I found the following links: {links}. I did not flag anything!"},
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Click Me"},
                            "action_id": "button_click",
                        },
                    }
                ],
                text=f"Hey there <@{message['user']}>!",
            )

async def main():
    logger.info("Initalizing app.")
    logging.getLogger("slack_sdk").setLevel(logging.DEBUG)
    webriskapi = WebRiskAPICaller()
    logger.info("WebRiskAPICaller intialized")
    handler = AsyncSocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    await handler.start_async()

# Start your app
if __name__ == "__main__":
    asyncio.run(main())