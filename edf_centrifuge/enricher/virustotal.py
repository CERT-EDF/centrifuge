"""VirusTotal enricher"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime

from vt import Client, url_id
from vt.error import APIError

from ..atom import URL, Digest, Domain, IPv4, IPv6
from ..helper.json import dumps
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'virustotal'
_LOGGER = get_logger('enricher.virustotal')
_CTX_EXT_CLIENT = 'client'


@dataclass(kw_only=True)
class VirusTotalEnricherConfig(EnricherConfig):
    """VirusTotal enricher config"""

    proxy: str | None = None
    agent: str = 'unknown'
    timeout: int = 5
    api_key: str | None = None
    trust_env: bool = False

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return bool(self.api_key)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.agent = dct.get('agent', 'unknown')
        instance.timeout = dct.get('timeout', 5)
        instance.api_key = dct.get('api_key')
        instance.trust_env = dct.get('trust_env', False)
        return instance


def _date_for_prop(attributes: dict, prop: str) -> datetime:
    timestamp = attributes.get(prop, 0)
    return datetime.fromtimestamp(timestamp).isoformat()


def _base_record(attributes: dict) -> dict:
    analysis_stats = attributes.get('last_analysis_stats', {})
    return {
        'malicious': analysis_stats.get('malicious'),
        'suspicious': analysis_stats.get('suspicious'),
        'undetected': analysis_stats.get('undetected'),
        'harmless': analysis_stats.get('harmless'),
    }


def _tls_record(attributes: dict) -> dict:
    tls_crt = attributes.get('last_https_certificate', {})
    return {
        'tls_jarm': attributes.get('jarm'),
        'tls_crt_cn': tls_crt.get('subject', {}).get('CN'),
        'tls_crt_san': dumps(tls_crt.get('extensions', {}).get('subject_alternative_name', [])),
        'tls_crt_date': _date_for_prop(
            attributes, 'last_https_certificate_date'
        ),
        'tls_crt_issuer': dumps(tls_crt.get('issuer', {})),
    }


async def _fetch(ctx: EnricherContext, path: str) -> Record:
    _LOGGER.info("requesting %s", path)
    client = ctx.ext[_CTX_EXT_CLIENT]
    try:
        data = await client.get_json_async(path)
    except APIError as exc:
        _LOGGER.error("vt api error: %s", exc)
        return {}
    return data.get('data', {}).get('attributes', {})


async def _enrich_url_impl(
    ctx: EnricherContext, url: URL, _feedback: Feedback
) -> Record:
    attributes = await _fetch(ctx, f'/urls/{url_id(url.value)}')
    record = _base_record(attributes)
    return record


async def _enrich_ipvx_impl(
    ctx: EnricherContext, ipvx: IPv4 | IPv6, _feedback: Feedback
) -> Record:
    if ipvx.parsed.is_private:
        return {}
    attributes = await _fetch(ctx, f'/ip_addresses/{ipvx.value}')
    record = _base_record(attributes)
    record.update(
        {
            'updated': _date_for_prop(attributes, 'last_modification_date'),
        }
    )
    record.update(_tls_record(attributes))
    return record


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    attributes = await _fetch(ctx, f'/domains/{domain.private_suffix}')
    record = _base_record(attributes)
    record.update(
        {
            'created': _date_for_prop(attributes, 'creation_date'),
            'updated': _date_for_prop(attributes, 'last_modification_date'),
            'registrar': attributes.get('registrar'),
            'whois_date': _date_for_prop(attributes, 'whois_date'),
        }
    )
    record.update(_tls_record(attributes))
    return record


async def _enrich_digest_impl(
    ctx: EnricherContext, digest: Digest, _feedback: Feedback
) -> Record:
    attributes = await _fetch(ctx, f'/files/{digest.value}')
    yara_results = attributes.get('crowdsourced_yara_results', {})
    threat_classif = attributes.get('popular_threat_classification', {})
    threat_label = threat_classif.get('suggested_threat_label', '')
    record = _base_record(attributes)
    record.update(
        {
            'yara_rules': [item['rule_name'] for item in yara_results],
            'last_analysis': _date_for_prop(attributes, 'last_analysis_date'),
            'first_submission': _date_for_prop(
                attributes, 'first_submission_date'
            ),
            'threat_label': threat_label,
        }
    )
    return record


async def _cleanup_ctx_impl(
    ctx: EnricherContext,
) -> AsyncIterator[None]:
    ctx.ext[_CTX_EXT_CLIENT] = Client(
        apikey=ctx.config.api_key,
        agent=ctx.config.agent,
        trust_env=ctx.config.trust_env,
        proxy=ctx.config.proxy,
    )
    _LOGGER.info("ready")
    yield
    _LOGGER.info("cleanup")
    client = ctx.ext.pop(_CTX_EXT_CLIENT)
    await client.close_async()


_FIELDS = (
    'malicious',
    'suspicious',
    'undetected',
    'harmless',
    'created',
    'updated',
    'registrar',
    'whois_date',
    'tls_jarm',
    'tls_crt_cn',
    'tls_crt_san',
    'tls_crt_date',
    'tls_crt_issuer',
    'yara_rules',
    'last_analysis',
    'first_submission',
    'threat_label',
)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipvx_impl,
        IPv6: _enrich_ipvx_impl,
        Domain: _enrich_domain_impl,
        Digest: _enrich_digest_impl,
    },
    cleanup_ctx_impl=_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, VirusTotalEnricherConfig)
