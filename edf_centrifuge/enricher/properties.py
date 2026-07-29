"""Properties enricher"""

from dataclasses import dataclass

from ..atom import (
    CVE,
    CWE,
    Digest,
    Email,
    MAC,
    Other,
    Phone,
    USB,
    UUID,
    URL,
    Domain,
    IPv4,
    IPv6,
    Atom,
)
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    noop_cleanup_ctx_impl,
    register_enricher,
)

GUID = 'properties'
_LOGGER = get_logger('enricher.properties')


@dataclass(kw_only=True)
class PropertiesEnricherConfig(EnricherConfig):
    """Properties engine config"""

    @property
    def valid(self) -> bool:
        return True


async def _enrich_default_impl(
    _ctx: EnricherContext, atom: Atom, _feedback: Feedback
) -> Record:
    return {'nature': atom.nature}


async def _enrich_ipvx_impl(
    ctx: EnricherContext, ipvx: IPv4 | IPv6, feedback: Feedback
) -> Record:
    record = await _enrich_default_impl(ctx, ipvx, feedback)
    record.update({'is_private': ipvx.parsed.is_private})
    return record


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, feedback: Feedback
) -> Record:
    record = await _enrich_default_impl(ctx, domain, feedback)
    record.update(
        {
            'prefix': domain.prefix,
            'public_suffix': domain.public_suffix,
            'private_suffix': domain.private_suffix,
        }
    )
    return record


async def _enrich_email_impl(
    ctx: EnricherContext, email: Email, feedback: Feedback
) -> Record:
    record = await _enrich_default_impl(ctx, email, feedback)
    domain = await _enrich_domain_impl(ctx, email.domain, feedback)
    record.update({'local': email.local, 'domain': domain})
    return record


async def _enrich_usb_impl(
    ctx: EnricherContext, usb: USB, feedback: Feedback
) -> Record:
    record = await _enrich_default_impl(ctx, usb, feedback)
    record.update({'vid': usb.vid, 'pid': usb.pid})
    return record


async def _enrich_url_impl(ctx: EnricherContext, url: URL, feedback: Feedback):
    record = await _enrich_default_impl(ctx, url, feedback)
    record.update({'host': url.host.value})
    enrich_func = _ENRICH_IMPL_MAP.get(type(url.host))
    if enrich_func:
        e_record = await enrich_func(ctx, url.host, set())
        record['host_ext'] = e_record
    record.update(
        {
            'scheme': url.parsed.scheme,
            'username': url.parsed.user,
            'password': url.parsed.password,
            'port': url.parsed.port,
            'path': url.parsed.path_safe,
            'query': url.parsed.query_string,
            'fragment': url.parsed.fragment,
            'suffixes': ''.join(url.parsed.suffixes),
        }
    )
    return record


_ENRICH_IMPL_MAP = {
    CVE: _enrich_default_impl,
    CWE: _enrich_default_impl,
    Digest: _enrich_default_impl,
    Domain: _enrich_domain_impl,
    Email: _enrich_email_impl,
    IPv4: _enrich_ipvx_impl,
    IPv6: _enrich_ipvx_impl,
    MAC: _enrich_default_impl,
    Other: _enrich_default_impl,
    Phone: _enrich_default_impl,
    URL: _enrich_url_impl,
    USB: _enrich_usb_impl,
    UUID: _enrich_default_impl,
}


_FIELDS = (
    'nature',
    'is_private',
    'domain',
    'name',
    'suffix',
    'host',
    'host_ext',
    'scheme',
    'username',
    'password',
    'port',
    'path',
    'query',
    'fragment',
    'suffixes',
)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map=_ENRICH_IMPL_MAP,
    cleanup_ctx_impl=noop_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, PropertiesEnricherConfig)
