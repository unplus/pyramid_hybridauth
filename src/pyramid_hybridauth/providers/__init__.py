from pyramid.httpexceptions import HTTPNotFound
from pyramid.settings import aslist
from .twitter import TwitterProvider
from .facebook import FaceBookProvider
from .google import GoogleProvider
from .yahoo import YahooProvider
from .ninja import NinjaProvider


PROVIDERS = {
    "twitter": TwitterProvider,
    "facebook": FaceBookProvider,
    "google": GoogleProvider,
    "yahoo": YahooProvider,
    "ninja": NinjaProvider,
}


def authenticate(request):
    provider = get_provider(request)
    if not provider:
        raise HTTPNotFound()

    if not provider.has_scene(request):
        raise HTTPNotFound()

    return provider.authenticate(request)


def view_callback(request):
    provider = get_provider(request)
    if not provider:
        raise HTTPNotFound()

    if not provider.has_scene(request):
        raise HTTPNotFound()

    return provider.access(request)


def get_provider(request):
    provider_name = request.matchdict.get("provider", None)
    if provider_name:
        return request.registry.auth_providers.get(provider_name, None)
    return None


def load_providers(config):
    config.registry.auth_providers = {}
    settings = config.registry.settings
    scenes = aslist(settings.get("hybridauth.scenes", ""))
    if len(scenes) < 1:
        raise Exception("Not config scenes.")

    for name, class_ in PROVIDERS.items():
        provider = class_(name, scenes, settings)
        if provider.enabled:
            config.add_auth_provider(provider)
