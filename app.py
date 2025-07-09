import logging
import os
import re
import urllib.parse as urllib_parse
from datetime import datetime, timedelta

import httpx

# import sqlalchemy
from dotenv import load_dotenv
from google.cloud import webrisk_v1
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, ListMetadata, ThreatHash

# This sample slack application uses SocketMode
# For the companion getting started setup guide, 
# see: https://slack.dev/bolt-python/tutorial/getting-started 

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"""
    (?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@
    )))
""", re.IGNORECASE | re.VERBOSE) # Yea this is pretty long, sorry...

# Initializes your app with your bot token
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

class WebRiskAPICaller:
    DB_NAME = 'webrisk.db'
    THREAT_TYPES_ENUM = [
        webrisk_v1.ThreatType.MALWARE,
        webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
        webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
        webrisk_v1.ThreatType.SOCIAL_ENGINEERING_EXTENDED_COVERAGE # we should warn when the bot flags extended_coverage phising
    ]
    DEFAULT_MIN_UPDATE_INTERVAL_SECONDS = 30 * 60 

    def __init__(self):
        self.engine = create_engine(f'sqlite:///{self.DB_NAME}') 
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)



def match_for_url(text):
    urls=[url.group(0) for url in URL_PATTERN.finditer(text)]
    if len(urls) == 0 or urls is None:
        return False
    webriskapi = WebRiskAPICaller()
    for url in urls:
        pass

# Listens to incoming messages that contain "hello"
@app.message()
def check_url(message, say):
    text = message.get("text", "")
    if "://" not in text and "." not in text:
        return
    else:
        ret = match_for_url(text)
        if not ret:
            return
    # say() sends a message to the channel where the event was triggered
    say(
        blocks=[
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"Hey there <@{message['user']}>!"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Click Me"},
                    "action_id": "button_click",
                },
            }
        ],
        text=f"Hey there <@{message['user']}>!",
    )


# @app.action("button_click")
# def action_button_click(body, ack, say):
#     # Acknowledge the action
#     ack()
#     say(f"<@{body['user']['id']}> clicked the button")


# Start your app
if __name__ == "__main__":
    SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"]).start()
