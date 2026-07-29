"""Centrifuge known CVE loader"""

from datetime import date
from json import JSONDecodeError, loads
from re import compile as regexp

from ..cache import Cache
from ..config import Resource, ResourceConfig, ResourceConfigMapping
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


GUID = 'known_cve'
_LOGGER = get_logger(f'loader.{GUID}')
_CVE_PATTERN = regexp(r'CVE-\d{4}-\d{4,7}')


def _extract_tags(cve: dict) -> set[str]:
    tags = set()
    items = cve.get('references') or []
    for item in items:
        if 'tags' in item and 'Exploit' in item['tags']:
            tags.add('exploit')
    return tags


def _extract_score(cve: dict) -> float:
    dct = cve.get('metrics') or {}
    for _, metrics in dct.items():
        for metric in metrics:
            if metric.get('type') == 'Primary':
                return metric['cvssData']['baseScore']
    return 0.0


def _extract_weaknesses(cve: dict) -> set[str]:
    items = cve.get('weaknesses') or []
    weaknesses = {
        item['value'] for weakness in items for item in weakness['description']
    }
    return weaknesses.difference({'NVD-CWE-Other', 'NVD-CWE-noinfo'})


def _extract_description(cve: dict) -> str | None:
    items = cve.get('descriptions') or []
    for item in items:
        if item['lang'] == 'en':
            return item['value']
    return None


def _parse_nvd(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source nvd is probably broken")
        return
    for vuln in data['vulnerabilities']:
        cve = vuln['cve']
        published, _ = cve['published'].split('.', 1)
        yield {
            'cve': cve['id'],
            'tags': _extract_tags(cve),
            'score': _extract_score(cve),
            'published': published,
            'weaknesses': _extract_weaknesses(cve),
            'description': _extract_description(cve),
        }


def _parse_kev(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source kev is probably broken")
        return
    for vuln in data['vulnerabilities']:
        yield {'cve': vuln['cveID']}


def _parse_exploitdb(text: str) -> RecordIterator:
    for rec in read_csv_text(text, fieldnames=['codes']):
        codes = rec['codes'].split(';')
        for code in codes:
            code = code.strip()
            if _CVE_PATTERN.fullmatch(code):
                yield {
                    'cve': code,
                    'tags': {'exploitdb'},
                }


def _parse_github_advisory(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except JSONDecodeError:
        _LOGGER.error("source ghsa is probably broken")
        return
    for advisory in data:
        aliases = advisory.get('aliases') or []
        ghsa_id = advisory.get('id')
        for alias in aliases:
            if _CVE_PATTERN.fullmatch(alias):
                yield {'cve': alias, 'ghsa_id': ghsa_id}


async def _generate_known_cve_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known cve records"""
    # fetch kev catalog
    kev = set()
    async for rec in fetch_resource_records(
        cache, config, Resource.KEV, _parse_kev
    ):
        kev.add(rec['cve'])
    # fetch exploitdb catalog
    exploitdb = set()
    async for rec in fetch_resource_records(
        cache, config, Resource.EXPLOITDB, _parse_exploitdb
    ):
        exploitdb.add(rec['cve'])
    # fetch github advisory catalog
    ghsa = {}
    async for rec in fetch_resource_records(
        cache, config, Resource.GHSA, _parse_github_advisory
    ):
        ghsa[rec['cve']] = rec['ghsa_id']
    # process nvd feed by year
    nvd_config = config[Resource.NVD]
    gen_config = {}
    for year in range(
        nvd_config.custom.get('first_year', 2002), date.today().year + 1
    ):
        nvd_guid = f'{Resource.NVD.value}_{year}'
        gen_config[nvd_guid] = ResourceConfig(
            url=nvd_config.url.format(year=year),
            proxy=nvd_config.proxy,
            custom={},
            headers=nvd_config.headers,
            validity=nvd_config.validity,
        )
        async for rec in fetch_resource_records(
            cache, gen_config, nvd_guid, _parse_nvd
        ):
            if rec['cve'] in kev:
                rec['tags'].add('kev')
            if rec['cve'] in exploitdb:
                rec['tags'].add('exploitdb')
            if rec['cve'] in ghsa:
                rec['tags'].add('github')
                ghsa_id = ghsa[rec['cve']]
                if ghsa_id:
                    rec['tags'].add(sanitize_tag(ghsa_id))
            yield (
                rec['cve'],
                dumps(sorted(rec['tags'])),
                str(rec['score']),
                rec['published'],
                dumps(sorted(rec['weaknesses'])),
                rec['description'],
            )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    cve text PRIMARY KEY,
    tags text,
    score text,
    published text,
    weaknesses text,
    description text
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_cve_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
