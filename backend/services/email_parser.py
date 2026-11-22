
import re
from urllib.parse import urlparse


def extract_email_features(sender, subject, body):
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        body
    )

    domains = []
    for url in urls:
        try:
            hostname = urlparse(url).hostname
        except ValueError:
            continue
        if hostname:
            domains.append(hostname)

    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "urls": urls,
        "domains": domains,
        "url_count": len(urls)
    }
