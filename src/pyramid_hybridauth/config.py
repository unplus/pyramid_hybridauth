from pyramid.path import DottedNameResolver
from pyramid.settings import asbool
from .exceptions import ProviderConfigError

CONFIG_PREFIX = "hybridauth"


def is_enabled(name, settings):
    return asbool(settings.get(f"{CONFIG_PREFIX}.{name}.enabled", False))


def get_callbacks(name, scenes, settings):
    resolver = DottedNameResolver()
    callbacks = {}
    for scene in scenes:
        try:
            callback = settings.get(
                f"{CONFIG_PREFIX}.{name}.callback.{scene}", None
            )
            callbacks[scene] = resolver.resolve(callback)
        except Exception:
            pass
    return callbacks


class OAuth1Config:
    def __init__(self, name, settings):
        self.name = name
        prefix = f"{CONFIG_PREFIX}.{self.name}"
        try:
            self.consumer_key = settings[f"{prefix}.consumer_key"]
            self.secret = settings[f"{prefix}.secret"]
            self.request_token_url = settings[f"{prefix}.request_token_url"]
            self.authorize_url = settings[f"{prefix}.authorize_url"]
            self.access_token_url = settings[f"{prefix}.access_token_url"]
        except KeyError as e:
            raise ProviderConfigError("OAuth1 env is not setting.", e)


class OAuth2Config:
    def __init__(self, name, settings):
        self.name = name
        prefix = f"{CONFIG_PREFIX}.{self.name}"
        try:
            self.client_id = settings[f"{prefix}.client_id"]
            self.secret = settings[f"{prefix}.secret"]
            self.authorize_url = settings[f"{prefix}.authorize_url"]
            self.access_token_url = settings[f"{prefix}.access_token_url"]
            self.request_url = settings[f"{prefix}.request_url"]
            self.scope = settings[f"{prefix}.scope"]
        except KeyError as e:
            raise ProviderConfigError("OAuth2 env is not setting.", e)
