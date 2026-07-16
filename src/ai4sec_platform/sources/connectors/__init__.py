from __future__ import annotations

from ai4sec_platform.sources.connectors.arxiv import ArxivConnector
from ai4sec_platform.sources.connectors.github import GithubConnector
from ai4sec_platform.sources.connectors.rss import RssConnector
from ai4sec_platform.sources.connectors.x_feed import XFeedConnector
from ai4sec_platform.sources.connectors.asis import AsisConnector
from ai4sec_platform.sources.connectors.awesome import AwesomeConnector
from ai4sec_platform.sources.connectors.anysearch import AnysearchConnector
from ai4sec_platform.sources.connectors.crawl4ai import Crawl4aiConnector
from ai4sec_platform.sources.connectors.huawei_repo import HuaweiRepoConnector
from ai4sec_platform.sources.connectors.cve import CveConnector
from ai4sec_platform.sources.connectors.firmware import FirmwareConnector
from ai4sec_platform.sources.connectors.mirror import MirrorConnector
from ai4sec_platform.sources.connectors.manual_import import ManualImportConnector


def all_connectors():
    return [
        ArxivConnector(), GithubConnector(), RssConnector(), XFeedConnector(), AsisConnector(), AwesomeConnector(),
        AnysearchConnector(), Crawl4aiConnector(), HuaweiRepoConnector(), CveConnector(), FirmwareConnector(),
        MirrorConnector(), ManualImportConnector(),
    ]
