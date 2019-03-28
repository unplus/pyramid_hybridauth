from pyramid.httpexceptions import HTTPNotFound, HTTPFound
from pyramid.settings import aslist
from .exceptions import ProviderAccessError
from .config import is_enabled, get_callbacks, OAuth1Config, OAuth2Config
from .services.twitter import TwitterService
from .services.facebook import FaceBookService
from .services.google import GoogleService
from .services.yahoo import YahooService
from .services.ninja import NinjaService

SERVICES = {
    "twitter": (OAuth1Config, TwitterService),
    "facebook": (OAuth2Config, FaceBookService),
    "google": (OAuth2Config, GoogleService),
    "yahoo": (OAuth2Config, YahooService),
    "ninja": (OAuth2Config, NinjaService),
}


def authenticate(request):
    provider = get_provider(request)
    if not provider:
        raise HTTPNotFound()

    if not provider.has_scene(request):
        raise HTTPNotFound()

    try:
        return provider.authenticate(request)
    except Exception as e:
        raise ProviderAccessError(e)


def view_callback(request):
    provider = get_provider(request)
    if not provider:
        raise HTTPNotFound()

    if not provider.has_scene(request):
        raise HTTPNotFound()

    try:
        return provider.access(request)
    except Exception as e:
        raise ProviderAccessError(e)


def add_auth_provider(config, provider):
    config.registry.auth_providers[provider.name] = provider


def get_provider(request):
    provider_name = request.matchdict.get("provider", None)
    if provider_name:
        return request.registry.auth_providers.get(provider_name, None)
    return None


class Provider:
    def __init__(self, config, service, callbacks):
        self.config = config
        self.service = service
        self.callbacks = callbacks

    def authenticate(self, request):
        scene = self._get_scene_name(request)
        callback_url = request.route_url(
            "auth_callback", provider=self.name, scene=scene
        )
        authorization_url = self.service.get_authorization_url(
            request, self.config, callback_url
        )
        return HTTPFound(location=authorization_url)

    def access(self, request):
        scene = self._get_scene_name(request)
        callback = self.callbacks[scene]

        callback_url = request.route_url(
            "auth_callback", provider=self.name, scene=scene
        )

        user = self.service.get_user(request, self.config, callback_url)
        return callback(request, self.name, user)

    @property
    def name(self):
        return self.config.name

    def has_scene(self, request):
        scene = self._get_scene_name(request)
        return not self.callbacks.get(scene) is None

    def _get_scene_name(self, request):
        return request.matchdict["scene"]


def load_providers(config):
    config.registry.auth_providers = {}
    settings = config.registry.settings
    scenes = aslist(settings.get("hybridauth.scenes", ""))
    if len(scenes) < 1:
        raise Exception("Not config scenes.")

    for name, class_ in SERVICES.items():
        if not is_enabled(name, settings):
            continue
        oauth_config = class_[0](name, settings)
        callbacks = get_callbacks(name, scenes, settings)
        service = class_[1]()
        provider = Provider(oauth_config, service, callbacks)
        config.add_auth_provider(provider)
