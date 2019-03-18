from rauth.service import OAuth1Service, OAuth2Service
from rauth.utils import parse_utf8_qsl

from pyramid.path import DottedNameResolver
from pyramid.httpexceptions import HTTPFound
from pyramid.settings import asbool

import json
from hashlib import sha1
from random import random

from ..exceptions import ProviderConfigError, ProviderAccessError

CONFIG_PREFIX = "hybridauth"


class AbstractProvider:
    def __init__(self, name, scenes, settings):
        self._name = name
        self._enabled = self._is_enabled(name, settings)
        if self._enabled:
            self._callbacks = self._get_callbacks(name, scenes, settings)
            self._load_config(settings)

    @property
    def name(self):
        return self._name

    @property
    def enabled(self):
        return self._enabled

    def authenticate(self, request):
        scene = self._get_scene_name(request)
        callback_url = request.route_url(
            "auth_callback", provider=self._name, scene=scene
        )
        return self._authenticate(request, callback_url)

    def access(self, request):
        scene = self._get_scene_name(request)
        callback = self._callbacks[scene]

        callback_url = request.route_url(
            "auth_callback", provider=self._name, scene=scene
        )
        session = self._create_session(request, callback_url)
        data = self._get_data(session)
        user = self._get_user(session, data)

        return callback(request, self._name, user)

    def has_scene(self, request):
        scene = self._get_scene_name(request)
        return not self._callbacks.get(scene) is None

    def _get_scene_name(self, request):
        return request.matchdict["scene"]

    def _is_enabled(self, name, settings):
        if not name or not settings:
            return False, None
        return asbool(settings.get(f"{CONFIG_PREFIX}.{name}.enabled", False))

    def _get_callbacks(self, name, scenes, settings):
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

    def _authenticate(self, request, callback_url):
        raise NotImplementedError("Override this method")

    def _load_config(self, settings):
        raise NotImplementedError("Override this method")

    def _create_session(self, request, callback_url):
        raise NotImplementedError("Override this method")

    def _get_data(self, session):
        raise NotImplementedError("Override this method")

    def _get_user(self, session, data):
        raise NotImplementedError("Override this method")


class AbstractOAuth1Provider(AbstractProvider):
    def __init__(self, name, scenes, settings):
        AbstractProvider.__init__(self, name, scenes, settings)

    def _load_config(self, settings):
        prefix = f"{CONFIG_PREFIX}.{self._name}"
        try:
            self._consumer_key = settings[f"{prefix}.consumer_key"]
            self._secret = settings[f"{prefix}.secret"]
            self._request_token_url = settings[f"{prefix}.request_token_url"]
            self._authorize_url = settings[f"{prefix}.authorize_url"]
            self._access_token_url = settings[f"{prefix}.access_token_url"]
        except KeyError as e:
            raise ProviderConfigError("OAuth2 env is not setting.", e)

    def _authenticate(self, request, callback_url):
        redirect_uri = callback_url
        service = self._get_service()
        request_token, request_token_secret = service.get_request_token(
            method="GET", params={"oauth_callback": redirect_uri}
        )
        authorize_url = service.get_authorize_url(request_token)

        request.session[f"{self._name}_request_token"] = request_token
        request.session[
            f"{self._name}_request_token_secret"
        ] = request_token_secret

        return HTTPFound(location=authorize_url)

    def _create_session(self, request, callback_url):
        token = request.GET.get("oauth_token", None)
        verifier = request.GET.get("oauth_verifier", None)

        request_token = request.session.get(
            f"{self._name}_request_token", None
        )  # noqa
        request_token_secret = request.session.get(
            f"{self._name}_request_token_secret", None
        )

        request.session[f"{self._name}_request_token"] = None
        request.session[f"{self._name}_request_token_secret"] = None

        if request_token and (token and verifier):
            service = self._get_service()

            session = service.get_auth_session(
                request_token,
                request_token_secret,
                method="POST",
                data={"oauth_verifier": verifier},
            )
            return session

        raise ProviderAccessError("Not found parameter.")

    def _get_data(self, session):
        response = session.access_token_response
        assert response.status_code == 200, response.reason
        return parse_utf8_qsl(response.text)

    def _get_service(self):
        service = OAuth1Service(
            name=self._name,
            request_token_url=self._request_token_url,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url,
            consumer_key=self._consumer_key,
            consumer_secret=self._secret,
        )
        return service


class AbstractOAuth2Provider(AbstractProvider):
    def __init__(self, name, scenes, settings):
        AbstractProvider.__init__(self, name, scenes, settings)

    def _load_config(self, settings):
        prefix = f"{CONFIG_PREFIX}.{self._name}"
        try:
            self._client_id = settings[f"{prefix}.client_id"]
            self._secret = settings[f"{prefix}.secret"]
            self._authorize_url = settings[f"{prefix}.authorize_url"]
            self._access_token_url = settings[f"{prefix}.access_token_url"]
            self._request_url = settings[f"{prefix}.request_url"]
            self._scope = settings[f"{prefix}.scope"]
        except KeyError as e:
            raise ProviderConfigError("OAuth2 env is not setting.", e)

    def _authenticate(self, request, callback_url):
        service = self._get_service()
        state = sha1(str(random())).hexdigest()
        params = {
            "redirect_uri": callback_url,
            "response_type": "code",
            "state": state,
        }
        if self._scope:
            params["scope"] = self._scope
        authorize_url = service.get_authorize_url(**params)

        return HTTPFound(location=authorize_url)

    def _create_session(self, request, callback_url):
        code = request.GET.get("code", None)
        if not code:
            raise ProviderAccessError("Not found code parameter.")
        service = self._get_service()
        params = {
            "code": code,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
        }
        return service.get_auth_session(data=params, decoder=json.loads)

    def _get_data(self, session):
        data = session.get(self._request_url).json()
        return data

    def _get_service(self):
        service = OAuth2Service(
            self._client_id,
            self._secret,
            name=self._name,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url,
        )
        return service


class User:
    def __init__(self, session, uid, display_name, data):
        self._session = session
        self._uid = uid
        self._display_name = display_name
        self._data = data

    def __str__(self):
        return (
            f"uid:{self._uid}, "
            f"display_name:{self._display_name}, "
            f"data:{self._data}"
        )

    @property
    def session(self):
        return self._session

    @property
    def uid(self):
        return self._uid

    @property
    def display_name(self):
        return self._display_name

    @property
    def data(self):
        return self._data
