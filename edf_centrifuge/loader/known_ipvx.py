"""Centrifuge known IPvX loader"""

from collections import defaultdict
from ipaddress import ip_address
from json import JSONDecodeError, loads

from yarl import URL

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..helper.logging import get_logger
from ..record import RecordIterator
from .base import (
    Loader,
    fetch_resource_records,
    read_csv_text,
    register_loader,
    sanitize_tag,
)

GUID = 'known_ipvx'
_LOGGER = get_logger(f'loader.{GUID}')


def _parse_tor(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source tor is probably broken")
        return
    for relay in data.get('relays', []):
        exit_addresses = relay.get('exit_addresses')
        if not exit_addresses:
            continue
        for ip in exit_addresses:
            yield {'ipvx': ip.strip(), 'tags': ['src.tor']}


def _parse_urlhaus(text: str) -> RecordIterator:
    """Parse URLhaus records"""
    text = '\n'.join(
        line
        for line in text.splitlines()
        if not line.startswith("#") and line.strip()
    )
    fieldnames = [
        'id',
        'dateadded',
        'url',
        'url_status',
        'last_online',
        'threat',
        'tags',
        'urlhaus_link',
        'reporter',
    ]
    for rec in read_csv_text(text, fieldnames=fieldnames):
        url_str = rec.get('url')
        if not url_str:
            continue
        try:
            url = URL(url_str)
        except ValueError:
            continue
        ipvx = url.host
        if not ipvx:
            continue
        try:
            ip_address(ipvx)
        except ValueError:
            continue
        tags = ['src.urlhaus']
        tags_str = rec.get('tags')
        if tags_str:
            for tag in tags_str.split(','):
                tag = sanitize_tag(tag)
                if tag:
                    tags.append(tag)
        threat = rec.get('threat')
        if threat:
            tags.append(sanitize_tag(threat))
        reporter = rec.get('reporter')
        if reporter:
            tags.append(sanitize_tag(reporter))
        tags.append(sanitize_tag(rec.get("url_status", "unknown")))
        yield {
            'ipvx': ipvx,
            'tags': tags,
        }


async def _generate_known_ipvx_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    rows = defaultdict(set)
    async for rec in fetch_resource_records(
        cache, config, Resource.TOR, _parse_tor
    ):
        rows[rec['ipvx']].update(rec['tags'])
    async for rec in fetch_resource_records(
        cache, config, Resource.URLHAUS, _parse_urlhaus
    ):
        rows[rec['ipvx']].update(rec['tags'])
    for ipvx, tags in rows.items():
        if not ipvx:
            continue
        yield (ipvx, dumps(sorted(tags)))


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    ipvx inet PRIMARY KEY,
    tags text
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_ipvx_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
