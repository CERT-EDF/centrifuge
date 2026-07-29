"""Centrifuge known USB loader"""

from collections import defaultdict
from collections.abc import Iterator
from json import JSONDecodeError, loads
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
)

GUID = 'known_usb'
_LOGGER = get_logger(f'loader.{GUID}')
_LOTHW_PATTERN = regexp(r'VID_(?P<vid>....)&PID_(?P<pid>....)')


def _lothw_instances(products: list[dict]) -> Iterator[tuple[str, str]]:
    for product in products:
        name = product['title']
        path = product['instancePath']
        if isinstance(path, str):
            yield name, path
            continue
        if isinstance(path, list):
            for item in path:
                for version, subpath in item.items():
                    yield f'{name}-{version}', subpath


def _parse_lothw(text: str) -> RecordIterator:
    try:
        item = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source lothw is probably broken")
        return
    for name, path in _lothw_instances(item['products']):
        match = _LOTHW_PATTERN.search(path)
        if not match:
            continue
        yield {
            'vid': match.group('vid').lower(),
            'pid': match.group('pid').lower(),
            'tags': ['src.lothw'],
            'product': name,
        }


def _parse_lin_usb_ids(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source lin usb ids is probably broken")
        return
    for vid, item in data.items():
        vid = vid.lower()
        vendor = item.get('name', '')
        yield {
            'vid': vid,
            'pid': '',
            'tags': ['src.linux'],
            'vendor': vendor,
        }
        for pid, product in item.get('products', {}).items():
            yield {
                'vid': vid,
                'pid': pid.lower(),
                'tags': ['src.lin_usb_ids'],
                'vendor': vendor,
                'product': product,
            }


def _parse_susp_usb_ids(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        yield {
            'vid': rec['vendor_id'].lower(),
            'pid': rec['product_id'].lower(),
            'tags': ['src.susp_usb_ids'],
            'product': rec['metadata_product'],
        }


async def _generate_known_usb_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    vendor = defaultdict(set)
    product = defaultdict(set)
    for guid, parse_func in (
        (Resource.LOTHW, _parse_lothw),
        (Resource.LIN_USB_IDS, _parse_lin_usb_ids),
        (Resource.SUSP_USB_IDS, _parse_susp_usb_ids),
    ):
        async for rec in fetch_resource_records(
            cache, config, guid, parse_func
        ):
            key = (rec['vid'], rec['pid'])
            tags[key].update(rec['tags'])
            if 'vendor' in rec:
                vendor[key].add(rec['vendor'])
            if 'product' in rec:
                product[key].add(rec['product'])
    for key in sorted(tags.keys()):
        vid, pid = key
        yield (
            vid,
            pid,
            dumps(sorted(tags[key])),
            ' | '.join(vendor[key]) if vendor[key] else '',
            ' | '.join(product[key]) if product[key] else '',
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    vid text,
    pid text,
    tags text,
    vendor text,
    product text,
    CONSTRAINT known_usb_pkey PRIMARY KEY (vid, pid)
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_usb_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
