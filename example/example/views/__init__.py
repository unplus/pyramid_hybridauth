from pyramid.view import view_config, exception_view_config
from pyramid.renderers import render_to_response
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid.security import (
    remember,
    forget,
    unauthenticated_userid,
    NO_PERMISSION_REQUIRED,
)
from pyramid_hybridauth import ProviderAccessError
from logging import getLogger

logger = getLogger(__name__)


@view_config(
    route_name="home", renderer="home.html", permission=NO_PERMISSION_REQUIRED
)
def home(request):
    login_user = unauthenticated_userid(request)
    if not login_user:
        return render_to_response("login.html", {}, request=request)

    out = {}
    for name in ["twitter", "facebook", "google", "ninja", "yahoo"]:
        out[name] = request.session.get(name, None)
    return out


@view_config(route_name="popup", renderer="popup.html")
def popup(request):
    provider_name = request.matchdict["provider"]
    return {"provider": provider_name}


@view_config(route_name="release", renderer="json")
def release(request):
    provider_name = request.matchdict["provider"]
    request.session[provider_name] = None
    return {}


@view_config(route_name="logout")
def logout(request):
    headers = forget(request)
    request.session.invalidate()
    return HTTPFound(location=request.route_url("home"), headers=headers)


@exception_view_config(ProviderAccessError)
def auth_error(request):
    logger.error(
        f"The error was: {request.exception}", exc_info=(request.exception)
    )
    return HTTPForbidden()


def twitter_login(request, provider_name, user):
    return _login(request, provider_name, user)


def twitter_join(request, provider_name, user):
    return _join(request, provider_name, user)


def facebook_login(request, provider_name, user):
    return _login(request, provider_name, user)


def facebook_join(request, provider_name, user):
    return _join(request, provider_name, user)


def google_login(request, provider_name, user):
    return _login(request, provider_name, user)


def google_join(request, provider_name, user):
    return _join(request, provider_name, user)


def ninja_login(request, provider_name, user):
    return _login(request, provider_name, user)


def ninja_join(request, provider_name, user):
    return _login(request, provider_name, user)


def yahoo_login(request, provider_name, user):
    return _login(request, provider_name, user)


def yahoo_join(request, provider_name, user):
    return _join(request, provider_name, user)


def join(request, provider_name, user):
    login_user = unauthenticated_userid(request)
    user = _convert_user(user)
    if login_user:
        request.session[provider_name] = user
        return HTTPFound(
            location=request.route_url("popup", provider=provider_name)
        )
    else:
        headers = remember(request, user.uid)
        request.session[provider_name] = user
        return HTTPFound(location=request.route_url("home"), headers=headers)


def _login(request, provider_name, user):
    user = _convert_user(user)
    headers = remember(request, user.uid)
    request.session[provider_name] = user
    return HTTPFound(location=request.route_url("home"), headers=headers)


def _join(request, provider_name, user):
    login_user = unauthenticated_userid(request)
    if not login_user:
        raise HTTPForbidden()
    user = _convert_user(user)
    request.session[provider_name] = user
    return HTTPFound(
        location=request.route_url("popup", provider=provider_name)
    )


class User:
    def __init__(self, uid, display_name):
        self.uid = uid
        self.display_name = display_name


def _convert_user(user):
    return User(user.uid, user.display_name)
