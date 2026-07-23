from __future__ import annotations

from ai4sec_platform.sources.connectors.news.arxiv import ArxivConnector
from ai4sec_platform.sources.connectors.news.github import GithubConnector
from ai4sec_platform.sources.connectors.news.rss import RssConnector
from ai4sec_platform.sources.connectors.vulnerabilities.anysearch import AnysearchConnector
from ai4sec_platform.sources.connectors.vulnerabilities.crawl4ai import Crawl4aiConnector
from ai4sec_platform.sources.connectors.vulnerabilities.manual_import import ManualImportConnector
from ai4sec_platform.sources.connectors.threats.huawei_repo import HuaweiRepoConnector
from ai4sec_platform.sources.connectors.threats.cve import CveConnector
from ai4sec_platform.sources.connectors.threats.firmware import FirmwareConnector
from ai4sec_platform.sources.connectors.threats.mirror import MirrorConnector
from ai4sec_platform.sources.connectors.threats.gitcode import GitCodeConnector
from ai4sec_platform.sources.connectors.threats.atomgit import AtomGitConnector
from ai4sec_platform.sources.connectors.threats.hiascend import HiAscendConnector
from ai4sec_platform.sources.connectors.threats.huawei_mirror import HuaweiMirrorConnector
from ai4sec_platform.sources.connectors.threats.openx_huawei import OpenXHuaweiConnector


def all_connectors():
    return [
        ArxivConnector(), GithubConnector(), RssConnector(),
        AnysearchConnector(), Crawl4aiConnector(), ManualImportConnector(), HuaweiRepoConnector(), CveConnector(),
        FirmwareConnector(), MirrorConnector(), GitCodeConnector(), AtomGitConnector(), HiAscendConnector(),
        HuaweiMirrorConnector(), OpenXHuaweiConnector(),
    ]
