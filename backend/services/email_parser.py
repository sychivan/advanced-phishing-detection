
import re
from urllib.parse import urlparse


def extract_email_features(sender, subject, body):
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        body
    )

    domains = [
        urlparse(url).hostname
        for url in urls
    ]

    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "urls": urls,
        "domains": domains,
        "url_count": len(urls)
    }
