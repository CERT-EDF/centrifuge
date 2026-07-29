"""Centrifuge known linux file loader"""

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
    convert_wildcard_to_like,
    fetch_resource_records,
    register_loader,
    sanitize_tag,
)

GUID = 'known_lin_file'
_LOGGER = get_logger(f'loader.{GUID}')


def _parse_gtfobins(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source gtfobins is probably broken")
        return
    for name, item in data['executables'].items():
        tags = {'src.gtfobins'}
        tags.update(
            {
                sanitize_tag(func_name)
                for func_name in item.get('functions', {}).keys()
            }
        )
        yield {
            'filename': convert_wildcard_to_like(name),
            'tags': tags,
        }


async def _generate_known_lin_file_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    async for rec in fetch_resource_records(
        cache, config, Resource.GTFOBINS, _parse_gtfobins
    ):
        tags[rec['filename']].update(rec['tags'])
    for filename in sorted(tags.keys()):
        if not filename:
            continue
        yield (
            filename,
            '%' in filename,
            dumps(sorted(tags[filename])),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    filename text NOT NULL,
    pattern boolean NOT NULL,
    tags text,
    PRIMARY KEY (filename, pattern)
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
    generate_rows_impl=_generate_known_lin_file_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
