"""Centrifuge known public network loader"""

from collections import defaultdict
from json import JSONDecodeError, loads

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..helper.logging import get_logger
from ..record import RecordIterator
from .base import (
    Loader,
    fetch_resource_records,
    register_loader,
    sanitize_tag,
)

GUID = 'known_public_network'
_LOGGER = get_logger(f'loader.{GUID}')


def _parse_aws(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source aws is probably broken")
        return
    for prefix in data.get('prefixes', []):
        tags = {'src.aws', 'ipv4', prefix['region'], prefix['service']}
        yield {'network': prefix['ip_prefix'], 'tags': tags}
    for prefix in data.get('ipv6_prefixes', []):
        tags = {'src.aws', 'ipv6', prefix['region'], prefix['service']}
        yield {'network': prefix['ipv6_prefix'], 'tags': tags}


def _parse_azure(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source azure is probably broken")
        return
    for value in data.get('values', []):
        props = value.get('properties', {})
        region = props.get('region')
        platform = props.get('platform')
        system_service = props.get('systemService')
        for prefix in props.get('addressPrefixes', []):
            tags = {
                'src.azure',
                region,
                platform,
                system_service,
                value.get('id'),
                value.get('name'),
            }
            tags.update(
                f'feature.{feat}' for feat in value.get('networkFeatures', [])
            )
            yield {'network': prefix, 'tags': tags}


def _parse_gcp(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source gcp is probably broken")
        return
    for prefix in data.get('prefixes', []):
        net = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
        if not net:
            continue
        yield {'network': net, 'tags': {'src.gcp', prefix.get('scope')}}


def _parse_protonvpn(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source protonvpn is probably broken")
        return
    for entry in data.get('data', []):
        tags = {'src.protonvpn', entry.get('domain'), entry.get('city')}
        if entry.get('Streaming'):
            tags.add('streaming')
        if entry.get('P2P'):
            tags.add('p2p')
        if entry.get('ipv4'):
            yield {'network': f"{entry['ipv4']}/32", 'tags': tags}
        if entry.get('ipv6'):
            yield {'network': f"{entry['ipv6']}/128", 'tags': tags}


def _parse_x4b(text: str, tags: set[str]) -> RecordIterator:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        yield {'network': line, 'tags': tags}


def _parse_x4b_dc(text: str) -> RecordIterator:
    yield from _parse_x4b(text, {'src.x4b_dc'})


def _parse_x4b_vpn(text: str) -> RecordIterator:
    yield from _parse_x4b(text, {'src.x4b_vpn'})


async def _generate_known_public_network_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    networks = defaultdict(set)
    for resource, parser in (
        (Resource.AWS, _parse_aws),
        (Resource.AZURE, _parse_azure),
        (Resource.GCP, _parse_gcp),
        (Resource.PROTONVPN, _parse_protonvpn),
        (Resource.X4B_DC, _parse_x4b_dc),
        (Resource.X4B_VPN, _parse_x4b_vpn),
    ):
        async for rec in fetch_resource_records(
            cache, config, resource, parser
        ):
            networks[rec['network']].update(rec['tags'])
    for net, tags in networks.items():
        tags = [sanitize_tag(tag) for tag in tags if tag]
        yield (net, dumps(tags))


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    network cidr PRIMARY KEY,
    tags text
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_public_network_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
