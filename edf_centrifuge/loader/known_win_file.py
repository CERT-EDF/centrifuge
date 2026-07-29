"""Centrifuge known windows file loader"""

from collections import defaultdict
from json import JSONDecodeError, loads
from pathlib import PureWindowsPath
from re import compile as regexp

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

GUID = 'known_win_file'
_LOGGER = get_logger(f'loader.{GUID}')
_WS_AND_COMMA = regexp(r'[,\s]+')


def _parse_lolrmm(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source lolrmm is probably broken")
        return
    for item in items:
        paths = item.get('Details', {}).get('InstallationPaths')
        if not paths:
            continue
        for path in paths:
            filename = PureWindowsPath(path).name.lower()
            filename = filename.lower()
            if not filename.endswith('.exe'):
                continue
            yield {
                'filename': filename,
                'tags': ['src.rmm', sanitize_tag(item['Name'])],
            }


def _parse_loldrv(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source loldrv is probably broken")
        return
    for item in items:
        for filename in item['Tags']:
            filename = filename.lower()
            if not filename.endswith('.sys'):
                continue
            category = sanitize_tag(item['Category'])
            category = category.replace('drivers', 'driver')
            yield {
                'filename': filename,
                'tags': ['src.loldrv', category],
            }


def _parse_lolbas(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source lolbas is probably broken")
        return
    for item in items:
        tags = {'src.lolbas'}
        for command in item['Commands']:
            tags.update(
                [
                    sanitize_tag(command['Category']),
                    sanitize_tag(command['MitreID']),
                ]
            )
        yield {
            'filename': item['Name'].lower(),
            'tags': list(tags),
        }


def _parse_filesec(text: str) -> RecordIterator:
    """Parse filesec CSV with headers: Extension,Function,OS

    Yields records like {'filename': '%<ext>', 'tags': [<sanitized function>, <os-tags>..., 'src.filesec']}
    """
    for row in read_csv_text(text):
        # Extension must be present under the exact 'Extension' header
        ext = row.get('Extension', '').strip()
        if not ext:
            continue
        if not ext.startswith('.'):
            ext = f'.{ext}'
        ext = ext.lower()

        func = row.get('Function', '').strip()
        os_field = row.get('OS', '').strip()

        tags = {'src.filesec'}
        if func:
            tags.add(sanitize_tag(func))
        if os_field:
            for os_name in _WS_AND_COMMA.split(os_field):
                os_name = os_name.strip()
                if not os_name:
                    continue
                tags.add(sanitize_tag(os_name))

        yield {'filename': f'%{ext}', 'tags': list(tags)}


def _parse_hijacklibs(text: str) -> RecordIterator:
    try:
        items = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source hijacklibs is probably broken")
        return
    for item in items:
        yield {
            'filename': item['Name'].lower(),
            'tags': ['src.hijacklibs', 'sideload-lib'],
        }
        for vuln_exe in item['VulnerableExecutables']:
            yield {
                'filename': PureWindowsPath(vuln_exe['Path']).name.lower(),
                'tags': ['src.hijacklibs', 'sideload-exe'],
            }


def _parse_loflcab(text: str) -> RecordIterator:
    """Parse loflcab JSON"""
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source loflcab is probably broken")
        return
    for rec in data:
        if rec.get('Type') != 'Binaries':
            continue

        name = rec.get('Name')
        if not name:
            continue

        tags = {'src.loflcab'}

        toolsets = rec.get('Toolsets', []) or []
        for toolset in toolsets:
            tags.add(sanitize_tag(toolset))

        functions = set()
        mitre = set()

        commands = rec.get('Commands', []) or []
        for cmd in commands:
            func = cmd.get('Function')
            if func:
                functions.add(sanitize_tag(func))

            techniques = cmd.get('MitreAttack', []) or []
            if techniques:
                mitre.update(techniques)

        tags.update(functions)
        tags.update(mitre)

        yield {
            'filename': name.lower(),
            'tags': sorted(tags),
        }


async def _generate_known_win_file_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    for guid, parse_func in (
        (Resource.LOLRMM, _parse_lolrmm),
        (Resource.LOLDRV, _parse_loldrv),
        (Resource.LOLBAS, _parse_lolbas),
        (Resource.FILESEC, _parse_filesec),
        (Resource.HIJACKLIBS, _parse_hijacklibs),
        (Resource.LOFLCAB, _parse_loflcab),
    ):
        async for rec in fetch_resource_records(
            cache, config, guid, parse_func
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
    generate_rows_impl=_generate_known_win_file_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
