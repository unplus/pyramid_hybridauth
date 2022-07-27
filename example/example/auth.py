import os

from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import UnencryptedCookieSessionFactoryConfig


def groupfinder(userid, request):
    return ["group:users"]


def includeme(config):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    config.include("pyramid_hybridauth", route_prefix="/auth")

    authn_policy = AuthTktAuthenticationPolicy(
        "examplesecret", callback=groupfinder
    )
    authz_policy = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig("examplesession")

    config.set_session_factory(session_factory)
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
