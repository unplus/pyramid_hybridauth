# -*- coding:utf-8 -*-
u"""
    pyramid_hybridauth
    ~~~~~~~~~~~~~~~~~~

    Pyramid Hybrid Auth Package.

    It provides Pyramid authentication in conjunction with external services

    using OAuth.

    :copyright: © unplus Inc. All rights reserved.
"""
from pyramid.settings import aslist
from pyramid.httpexceptions import HTTPNotFound
from pyramid.security import NO_PERMISSION_REQUIRED

from pyramid_hybridauth.providers import PROVIDERS


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
    provider_name = request.matchdict.get('provider', None)
    if provider_name:
        return request.registry.auth_providers.get(provider_name, None)
    return None


def add_auth_provider(config, provider):
    config.registry.auth_providers[provider.name] = provider


def load_providers(config):
    config.registry.auth_providers = {}
    settings = config.registry.settings
    scenes = aslist(settings.get('hybridauth.scenes', ''))
    if len(scenes) < 1:
        raise Exception('Not config scenes.')

    for name, class_ in PROVIDERS.items():
        provider = class_(name, scenes, settings)
        if provider.enabled:
            config.add_auth_provider(provider)


def includeme(config):

    config.add_route('auth_authenticate', '/{provider}/{scene}/authenticate')
    config.add_view(
        authenticate,
        route_name='auth_authenticate',
        permission=NO_PERMISSION_REQUIRED
    )

    config.add_route('auth_callback', '/{provider}/{scene}/callback')
    config.add_view(
        view_callback,
        route_name='auth_callback',
        permission=NO_PERMISSION_REQUIRED
    )

    config.add_directive('add_auth_provider', add_auth_provider)

    load_providers(config)
