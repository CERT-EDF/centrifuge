"""Censys enricher"""

from dataclasses import dataclass, field

from ..atom import URL, IPv4, IPv6
from ..helper.aiohttp import CTX_EXT_SESSION, aiohttp_cleanup_ctx_impl
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'censys'
_LOGGER = get_logger('enricher.censys')


@dataclass(kw_only=True)
class CensysEnricherConfig(EnricherConfig):
    """Censys enricher config"""

    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    org_id: str | None = None
    api_key: str | None = None

    @property
    def valid(self) -> bool:
        return bool(self.api_key)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.headers = dct.get('headers', {})
        instance.org_id = dct.get('org_id')
        instance.api_key = dct.get('api_key')
        return instance


async def _fetch_host(ctx: EnricherContext, ipvx: str) -> Record:
    session = ctx.ext[CTX_EXT_SESSION]
    params = {}
    if ctx.config.org_id:
        params['organization_id'] = ctx.config.org_id
    headers = {
        'Accept': 'application/vnd.censys.api.v3.host.v1+json',
        'Authorization': f'Bearer {ctx.config.api_key}',
    }
    endpoint = f'https://api.platform.censys.io/v3/global/asset/host/{ipvx}'
    async with session.get(
        endpoint, headers=headers, params=params
    ) as response:
        if response.status != 200:
            return []
        body = await response.json()
        return {'info': body['result']['resource']}


async def _enrich_url_impl(
    _ctx: EnricherContext, url: URL, feedback: Feedback
) -> Record:
    if not isinstance(url.host, (IPv4, IPv6)):
        return {}
    feedback.recurse = True
    return {'atom': url.host}


async def _enrich_ipvx_impl(
    ctx: EnricherContext, ipvx: IPv4 | IPv6, _feedback: Feedback
) -> Record:
    if ipvx.parsed.is_private:
        return {}
    return await _fetch_host(ctx, ipvx.value)


_FIELDS = ('info',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipvx_impl,
        IPv6: _enrich_ipvx_impl,
    },
    cleanup_ctx_impl=aiohttp_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, CensysEnricherConfig)
