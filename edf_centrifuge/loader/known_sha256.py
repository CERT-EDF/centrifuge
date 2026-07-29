"""Centrifuge known SHA-256 loader"""

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

GUID = 'known_sha256'
_LOGGER = get_logger(f'loader.{GUID}')


def _parse_loldrv(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source loldrv is probably broken")
        return
    for item in items:
        for vuln_sample in item['KnownVulnerableSamples']:
            sha256 = vuln_sample.get('SHA256')
            if not sha256:
                continue
            category = sanitize_tag(item['Category'])
            category = category.replace('drivers', 'driver')
            yield {
                'sha256': sha256.lower(),
                'tags': ['src.loldrv', category],
            }


def _parse_hijacklibs(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source hijacklibs is probably broken")
        return
    for item in items:
        for vuln_exe in item['VulnerableExecutables']:
            for sha256 in vuln_exe.get('SHA256', []):
                yield {
                    'sha256': sha256.lower(),
                    'tags': ['src.hijacklibs', 'sideload-exe'],
                }


def _parse_bootloaders(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source bootloaders is probably broken")
        return
    for item in items:
        known_vulnerables_samples = item.get('KnownVulnerableSamples', [])
        for vuln_sample in known_vulnerables_samples:
            tags = set()
            company = item.get('Company')
            if company:
                tags.add(sanitize_tag(company))
            creation_timestamp = vuln_sample.get('CreationTimestamp')
            if creation_timestamp:
                tags.add(f"created:{creation_timestamp[:10]}")
            internal_name = vuln_sample.get('InternalName')
            if internal_name:
                tags.add(sanitize_tag(internal_name))
            file_name = vuln_sample.get('FileName')
            if file_name:
                tags.add(sanitize_tag(file_name))
            auth_hash = vuln_sample.get('Authentihash', {})
            auth_sha256 = auth_hash.get('SHA256')
            if auth_sha256:
                yield {
                    'sha256': auth_sha256.lower(),
                    'tags': ['src.bootloaders.authentihash'],
                }
            sha256 = vuln_sample.get('SHA256')
            if sha256:
                yield {
                    'sha256': sha256.lower(),
                    'tags': ['src.bootloaders'],
                }


async def _generate_known_sha256_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    for guid, parse_func in (
        (Resource.LOLDRV, _parse_loldrv),
        (Resource.HIJACKLIBS, _parse_hijacklibs),
        (Resource.BOOTLOADERS, _parse_bootloaders),
    ):
        async for rec in fetch_resource_records(
            cache, config, guid, parse_func
        ):
            tags[rec['sha256']].update(rec['tags'])
    for sha256 in sorted(tags.keys()):
        yield (sha256, dumps(sorted(tags[sha256])))


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    sha256 text PRIMARY KEY,
    tags text
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_sha256_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
