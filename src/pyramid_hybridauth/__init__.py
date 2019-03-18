from pyramid.security import NO_PERMISSION_REQUIRED
from .providers import authenticate, view_callback, load_providers
from .exceptions import ProviderAccessError, ProviderConfigError # noqa


def add_auth_provider(config, provider):
    config.registry.auth_providers[provider.name] = provider


def includeme(config):

    config.add_route("auth_authenticate", "/{provider}/{scene}/authenticate")
    config.add_view(
        authenticate,
        route_name="auth_authenticate",
        permission=NO_PERMISSION_REQUIRED,
    )

    config.add_route("auth_callback", "/{provider}/{scene}/callback")
    config.add_view(
        view_callback,
        route_name="auth_callback",
        permission=NO_PERMISSION_REQUIRED,
    )

    config.add_directive("add_auth_provider", add_auth_provider)

    load_providers(config)
