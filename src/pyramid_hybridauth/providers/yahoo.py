from rauth.service import OAuth2Service
from rauth.utils import ENTITY_METHODS
import base64
from .provider import AbstractOAuth2Provider, User


class YahooService(OAuth2Service):
    def get_raw_access_token(self, method="POST", **kwargs):

        key = "params"
        if method in ENTITY_METHODS:
            key = "data"

        kwargs.setdefault(key, {})

        base_auth = self._create_basic_auth()
        kwargs.setdefault("headers", {})
        kwargs["headers"].update(
            {"Authorization": "Basic {0}".format(base_auth)}
        )

        session = self.get_session()
        self.access_token_response = session.request(
            method, self.access_token_url, **kwargs
        )
        return self.access_token_response

    def _create_basic_auth(self):
        key = f"{self.client_id}:{self.client_secret}".encode("utf-8")
        return base64.b64encode(key).decode("utf-8")


class YahooProvider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data["user_id"]
        display_name = data.get("name")
        return User(session, uid, display_name, data)

    def _get_service(self):
        service = YahooService(
            self._client_id,
            self._secret,
            name=self._name,
            authorize_url=self._authorize_url,
            access_token_url=self._access_token_url,
        )
        return service
