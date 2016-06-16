# -*- coding:utf-8 -*-
from pyramid.config import Configurator
from pyramid.security import Allow, Everyone, NO_PERMISSION_REQUIRED
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import UnencryptedCookieSessionFactoryConfig


def groupfinder(userid, request):
    return ['group:users']


class RootFactory(object):
    __acl__ = [
        (Allow, Everyone, 'everyone'),
        (Allow, 'group:users', 'user')
    ]

    def __init__(self, request):
        pass


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    authn_policy = AuthTktAuthenticationPolicy(
        'examplesecret',
        callback=groupfinder
    )
    authz_policy = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig('examplesession')

    config = Configurator(settings=settings,
                          root_factory='example.RootFactory',
                          session_factory=session_factory)
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    config.include('pyramid_chameleon')
    config.include('pyramid_hybridauth', route_prefix='/auth')

    config.set_default_permission('user')
    config.add_static_view(
        'static',
        'static',
        cache_max_age=3600, permission=NO_PERMISSION_REQUIRED
    )
    config.add_route('home', '/')
    config.add_route('popup', '/popup/{provider}')
    config.add_route('release', '/release/{provider}')
    config.add_route('logout', '/logout')
    config.scan()
    return config.make_wsgi_app()
