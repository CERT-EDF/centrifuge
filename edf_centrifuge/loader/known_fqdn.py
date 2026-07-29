"""Centrifuge known FQDN loader"""

import ipaddress
from collections import defaultdict
from json import loads
from re import compile as regexp

from yarl import URL

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..record import RecordIterator
from .base import (
    Loader,
    convert_wildcard_to_like,
    fetch_resource_records,
    read_csv_text,
    register_loader,
    sanitize_tag,
)

GUID = 'known_fqdn'
_FQDN_PATTERN = regexp(r'(?P<fqdn>[a-z\d\-\*]+(\.[a-z\d\-\*]+)+)')
_URL_FQDN_PATTERN = regexp(r'https?://(?P<fqdn>[a-z\d\-\*]+(\.[a-z\d\-\*]+)+)')


def _parse_lolc2(text: str) -> RecordIterator:
    items = loads(text)
    for name, info in items.items():
        fqdn_set = set()
        for item in info['detection']:
            match = _URL_FQDN_PATTERN.search(item.lower())
            if not match:
                continue
            fqdn_set.add(match.group('fqdn').rstrip('*'))
        for fqdn in fqdn_set:
            yield {
                'fqdn': convert_wildcard_to_like(fqdn),
                'info': {'tags': ['src.lolc2', sanitize_tag(name)]},
            }


def _parse_lolrmm(text: str) -> RecordIterator:
    items = loads(text)
    for item in items:
        for network in item['Artifacts'].get('Network', []):
            fqdn_set = set()
            for fqdn in network['Domains']:
                match = _FQDN_PATTERN.match(fqdn.lower())
                if not match:
                    continue
                fqdn_set.add(match.group('fqdn'))
            for fqdn in fqdn_set:
                yield {
                    'fqdn': convert_wildcard_to_like(fqdn),
                    'info': {
                        'tags': ['src.lolrmm', sanitize_tag(item['Name'])]
                    },
                }


def _parse_lots(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        match = _FQDN_PATTERN.match(rec['Website'].lower())
        if not match:
            continue
        tags = {'src.lots'}
        for tag in rec['Tags'].split():
            tags.add(sanitize_tag(tag))
        yield {
            'fqdn': convert_wildcard_to_like(match.group('fqdn')),
            'info': {'tags': list(tags)},
        }


def _parse_lottun(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        match = _FQDN_PATTERN.match(rec['domain'].lower())
        if not match:
            continue
        yield {
            'fqdn': convert_wildcard_to_like(match.group('fqdn')),
            'info': {'tags': ['src.lottun', sanitize_tag(rec['name'])]},
        }


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
        fqdn = url.host
        if not fqdn:
            continue
        try:
            ipaddress.ip_address(fqdn)
            continue
        except ValueError:
            pass
        tags = {'src.urlhaus'}
        tags_str = rec.get('tags')
        if tags_str:
            for tag in tags_str.split(','):
                tag = sanitize_tag(tag)
                if tag:
                    tags.add(tag)
        threat = rec.get('threat')
        if threat:
            tags.add(sanitize_tag(threat))
        reporter = rec.get('reporter')
        if reporter:
            tags.add(sanitize_tag(reporter))
        tags.add(sanitize_tag(rec.get("url_status", "unknown")))
        yield {
            'fqdn': fqdn,
            'info': {'tags': list(tags)},
        }


def _parse_tranco(text: str) -> RecordIterator:
    for rec in read_csv_text(text, fieldnames=['rank', 'domain']):
        yield {
            'fqdn': rec['domain'],
            'info': {'tags': ['src.tranco'], 'tranco_rank': int(rec['rank'])},
        }


def _parse_email_bl(text: str) -> RecordIterator:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        yield {
            'fqdn': line,
            'info': {'tags': ['src.email_bl']},
        }


async def _generate_known_fqdn_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    info = defaultdict(dict)
    for resource, parse_func in (
        (Resource.LOLC2, _parse_lolc2),
        (Resource.LOLRMM, _parse_lolrmm),
        (Resource.LOTS, _parse_lots),
        (Resource.TRANCO, _parse_tranco),
        (Resource.LOTTUN, _parse_lottun),
        (Resource.URLHAUS, _parse_urlhaus),
        (Resource.EMAIL_BL, _parse_email_bl),
    ):
        async for rec in fetch_resource_records(
            cache, config, resource, parse_func
        ):
            fqdn = rec['fqdn']
            tags = rec['info'].pop('tags', [])
            if 'tags' not in info[fqdn]:
                info[fqdn]['tags'] = set()
            info[fqdn]['tags'].update(tags)
            info[fqdn].update(rec['info'])
    for fqdn in sorted(info.keys()):
        if not fqdn:
            continue
        fqdn_info = info[fqdn]
        fqdn_info['tags'] = list(sorted(fqdn_info['tags']))
        yield (fqdn, '%' in fqdn, dumps(fqdn_info))


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    fqdn text NOT NULL,
    pattern boolean NOT NULL,
    info text,
    PRIMARY KEY (fqdn, pattern)
) PARTITION BY LIST (pattern);
'''
_CREATE_PART_PATTERN_T = '''
CREATE TABLE {schema}.{table}_pattern_t
PARTITION OF {schema}.{table}
FOR VALUES IN (TRUE);
'''
_CREATE_PART_PATTERN_F = '''
CREATE TABLE {schema}.{table}_pattern_f
PARTITION OF {schema}.{table}
FOR VALUES IN (FALSE);
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_fqdn_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
