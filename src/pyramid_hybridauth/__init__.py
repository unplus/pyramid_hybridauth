from pyramid.security import NO_PERMISSION_REQUIRED
from .provider import (
    authenticate,
    view_callback,
    load_providers,
    add_auth_provider,
)
from .exceptions import ProviderAccessError, ProviderConfigError  # noqa


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
