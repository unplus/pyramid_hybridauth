from . import Service, User
from oauthlib.common import to_unicode
from requests_oauthlib import OAuth2Session
from json import dumps


class NinjaService(Service):
    def get_authorization_url(self, request, config, callback_url):
        oauth = OAuth2Session(
            config.client_id, scope=config.scope, redirect_uri=callback_url
        )
        authorization_url, _ = oauth.authorization_url(config.authorize_url)
        return authorization_url

    def get_user(self, request, config, callback_url):
        oauth = OAuth2Session(
            config.client_id, scope=config.scope, redirect_uri=callback_url
        )
        oauth = ninja_compliance_fix(oauth)
        oauth.fetch_token(
            config.access_token_url,
            client_secret=config.secret,
            authorization_response=request.url,
            include_client_id=True,
        )
        response = oauth.get(config.request_url)
        data = response.json()
        uid = data["id"]
        display_name = data.get("nickname")
        return User(uid, display_name, data)


def ninja_compliance_fix(session):
    def _compliance_fix(r):
        if r.status_code != 200:
            return r

        token = r.json()
        expires_in = token.get("expires_in")
        if expires_in and int(expires_in) < 1:
            token.pop("expires_in")
        r._content = to_unicode(dumps(token)).encode("UTF-8")
        return r

    session.register_compliance_hook("access_token_response", _compliance_fix)
    return session
