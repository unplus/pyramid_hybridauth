# -*- coding:utf-8 -*-
u"""
    pyramid_hybridauth.providers
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from pyramid.settings import asbool
from rauth.service import OAuth1Service, OAuth2Service
import json
import base64

CONFIG_PREFIX = 'hybridauth'


def response_decoder(response):
    if response is None:
        return None

    if isinstance(response, bytes):
        response = response.decode('utf-8')

    return json.loads(response)


class AbstractProvider(object):

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
            'auth_callback',
            provider=self._name,
            scene=scene
        )
        return self._authenticate(request, callback_url)

    def access(self, request):
        scene = self._get_scene_name(request)
        callback = self._callbacks[scene]

        callback_url = request.route_url(
            'auth_callback',
            provider=self._name,
            scene=scene
        )
        session = self._create_session(request, callback_url)
        data = self._get_data(session)
        user = self._get_user(session, data)

        return callback(request, self._name, user)

    def has_scene(self, request):
        scene = self._get_scene_name(request)
        return not self._callbacks.get(scene) is None

    def _get_scene_name(self, request):
        return request.matchdict['scene']

    def _is_enabled(self, name, settings):
        if not name or not settings:
            return False, None
        config_key = "{0}.{1}.enabled".format(CONFIG_PREFIX, name)
        return asbool(settings.get(config_key, False))

    def _get_callbacks(self, name, scenes, settings):
        from pyramid.path import DottedNameResolver
        resolver = DottedNameResolver()
        callbacks = {}
        for scene in scenes:
            try:
                config_key = "{0}.{1}.callback.{2}".format(
                    CONFIG_PREFIX, name, scene)
                callback = settings.get(config_key, None)
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

    @property
    def token_key(self):
        return "{0}_request_token".format(self._name)

    @property
    def token_secret_key(self):
        return "{0}_request_token_secret".format(self._name)

    def _load_config(self, settings):
        prefix = '{0}.{1}'.format(CONFIG_PREFIX, self._name)
        try:
            self._consumer_key = settings['%s.consumer_key' % prefix]
            self._secret = settings['%s.secret' % prefix]
            self._request_token_url = settings['%s.request_token_url' % prefix]
            self._authorize_url = settings['%s.authorize_url' % prefix]
            self._access_token_url = settings['%s.access_token_url' % prefix]
        except KeyError as e:
            raise ProviderConfigError('OAuth2 env is not setting.', e)

    def _authenticate(self, request, callback_url):
        redirect_uri = callback_url
        service = self._get_service()
        request_token, request_token_secret = service.get_request_token(
            method='GET',
            params={'oauth_callback': redirect_uri})
        authorize_url = service.get_authorize_url(request_token)

        request.session[self.token_key] = request_token
        request.session[self.token_secret_key] = request_token_secret

        from pyramid.httpexceptions import HTTPFound
        return HTTPFound(location=authorize_url)

    def _create_session(self, request, callback_url):
        token = request.GET.get('oauth_token', None)
        verifier = request.GET.get('oauth_verifier', None)

        request_token = request.session.get(self.token_key, None)
        request_token_secret = request.session.get(self.token_secret_key, None)

        request.session[self.token_key] = None
        request.session[self.token_secret_key] = None

        if request_token and (token and verifier):
            service = self._get_service()

            session = service.get_auth_session(
                request_token,
                request_token_secret,
                method='POST',
                data={'oauth_verifier': verifier})
            return session

        raise ProviderAccessError('Not found parameter.')

    def _get_data(self, session):
        response = session.access_token_response
        assert response.status_code == 200, response.reason

        from rauth.utils import parse_utf8_qsl
        return parse_utf8_qsl(response.text)

    def _get_service(self):
        service = OAuth1Service(
            name=self._name,
            request_token_url=self._request_token_url,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url,
            consumer_key=self._consumer_key,
            consumer_secret=self._secret)
        return service


class AbstractOAuth2Provider(AbstractProvider):

    def __init__(self, name, scenes, settings):
        AbstractProvider.__init__(self, name, scenes, settings)

    def _load_config(self, settings):
        prefix = '%s.%s' % (CONFIG_PREFIX, self._name)
        try:
            self._client_id = settings['%s.client_id' % prefix]
            self._secret = settings['%s.secret' % prefix]
            self._authorize_url = settings['%s.authorize_url' % prefix]
            self._access_token_url = settings['%s.access_token_url' % prefix]
            self._request_url = settings['%s.request_url' % prefix]
            self._scope = settings['%s.scope' % prefix]
        except KeyError as e:
            raise ProviderConfigError('OAuth2 env is not setting.', e)

    def _authenticate(self, request, callback_url):
        from hashlib import sha1
        from random import random

        service = self._get_service()
        state = sha1(str(random()).encode('utf-8')).hexdigest()
        params = {
            'redirect_uri': callback_url,
            'response_type': 'code',
            'state': state,
        }
        if self._scope:
            params['scope'] = self._scope
        authorize_url = service.get_authorize_url(**params)
        from pyramid.httpexceptions import HTTPFound
        return HTTPFound(location=authorize_url)

    def _create_session(self, request, callback_url):
        code = request.GET.get('code', None)
        if not code:
            raise ProviderAccessError('Not found code parameter.')
        service = self._get_service()
        params = {
            'code': code,
            'redirect_uri': callback_url,
            'grant_type': 'authorization_code'
        }
        return service.get_auth_session(data=params, decoder=response_decoder)

    def _get_data(self, session):
        data = session.get(self._request_url).json()
        return data

    def _get_service(self):
        service = OAuth2Service(
            self._client_id,
            self._secret,
            name=self._name,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url)
        return service


class TwitterOAuth1Provider(AbstractOAuth1Provider):
    def _get_user(self, session, data):
        uid = data['user_id']
        display_name = data.get('screen_name')
        return User(session, uid, display_name, data)


class FaceBookOAuth2Provider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data['id']
        display_name = data.get('name')
        return User(session, uid, display_name, data)

    def _create_session(self, request, callback_url):
        code = request.GET.get('code', None)
        if not code:
            raise ProviderAccessError('Not found code parameter.')
        service = self._get_service()
        params = {'code': code, 'redirect_uri': callback_url}
        return service.get_auth_session(data=params)


class GoogleOAuth2Provider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data['id']
        display_name = data.get('name')
        return User(session, uid, display_name, data)


class NinjaOAuth2Provider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data['id']
        display_name = data.get('nickname')
        return User(session, uid, display_name, data)


class YahooOAuth2Provider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data['user_id']
        display_name = data.get('name')
        return User(session, uid, display_name, data)

    def _get_service(self):
        service = YahooService(
            self._client_id,
            self._secret,
            name=self._name,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url)
        return service


class User(object):
    def __init__(self, session, uid, display_name, data):
        self._session = session
        self._uid = uid
        self._display_name = display_name
        self._data = data

    def __str__(self):
        return "uid:{0}, display_name:{1}, data:{2}".format(
            self._uid, self._display_name, self._data
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


class YahooService(OAuth2Service):

    def get_raw_access_token(self, method='POST', **kwargs):

        from rauth.utils import ENTITY_METHODS
        key = 'params'
        if method in ENTITY_METHODS:
            key = 'data'

        kwargs.setdefault(key, {})

        base_auth = self._create_basic_auth()
        kwargs.setdefault('headers', {})
        kwargs['headers'].update({
            'Authorization': "Basic {0}".format(base_auth)
        })

        session = self.get_session()
        self.access_token_response = session.request(method,
                                                     self.access_token_url,
                                                     **kwargs)
        return self.access_token_response

    def _create_basic_auth(self):
        key = "{0}:{1}".format(self.client_id, self.client_secret)
        return base64.b64encode(key.encode('utf-8')).decode('utf-8')


class ProviderConfigError(Exception):
    pass


class ProviderAccessError(Exception):
    pass

PROVIDERS = {
    'twitter': TwitterOAuth1Provider,
    'facebook': FaceBookOAuth2Provider,
    'google': GoogleOAuth2Provider,
    'ninja': NinjaOAuth2Provider,
    'yahoo': YahooOAuth2Provider,
}
