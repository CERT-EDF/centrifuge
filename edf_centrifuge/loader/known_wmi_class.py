"""Centrifuge known wmi class loader"""

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
)

GUID = 'known_wmi_class'
_LOGGER = get_logger(f'loader.{GUID}')


def _parse_loflcab(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source loflcab is probably broken")
        return
    for rec in data:
        if rec.get('Type') != 'WMI':
            continue
        name = rec.get('Name')
        if not name:
            continue
        mitre = set()
        commands = rec.get('Commands', []) or []
        for cmd in commands:
            if not cmd:
                continue
            techniques = cmd.get('MitreAttack', []) or []
            if techniques:
                mitre.update(techniques)
        yield {
            'wmi_class': name,
            'description': rec.get('Description', ''),
            'mitre': sorted(mitre),
            'url': rec.get('Url', ''),
        }


async def _generate_known_wmi_class_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known wmi class records"""
    classes = set()
    desc = {}
    mitre = defaultdict(set)
    url = {}
    async for rec in fetch_resource_records(
        cache, config, Resource.LOFLCAB, _parse_loflcab
    ):
        wmi_class = rec['wmi_class']
        classes.add(wmi_class)
        if rec['description']:
            desc[wmi_class] = rec['description']
        if rec['url']:
            url[wmi_class] = rec['url']
        mitre[wmi_class].update(rec['mitre'])
    for wmi_class in sorted(classes):
        if not wmi_class:
            continue
        yield (
            wmi_class,
            '%' in wmi_class,
            desc.get(wmi_class, ''),
            dumps(sorted(mitre[wmi_class])),
            url.get(wmi_class, ''),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    wmi_class text NOT NULL,
    pattern boolean NOT NULL,
    description text,
    mitre text,
    url text,
    PRIMARY KEY (wmi_class, pattern)
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
    generate_rows_impl=_generate_known_wmi_class_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
