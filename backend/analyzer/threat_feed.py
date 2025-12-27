import feedparser
import traceback
import logging

logger = logging.getLogger(__name__)

RSS_URL = "https://feeds.feedburner.com/TheHackersNews"

async def get_recent_threats():
    """
    Fetches the latest cybersecurity news from The Hacker News RSS feed.
    """
    try:
        # Parse the RSS feed
        feed = feedparser.parse(RSS_URL)
        
        threats = []
        # Return empty list if feed is down or empty
        if not feed.entries:
            return []

        # Get top 5 entries
        for entry in feed.entries[:5]:
            threats.append({
                "title": entry.title,
                "link": entry.link,
                # Add default risk/verdict fields so the frontend table doesn't break
                "verdict": "News",
                "risk_score": 0
            })
        return threats

    except Exception as e:
        logger.error(f"Threat Feed Error: {e}")
        traceback.print_exc()  # 🔥 Traceback added
        return []