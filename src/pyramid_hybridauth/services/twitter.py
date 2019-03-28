from . import Service, User
from ..exceptions import ProviderAccessError
from requests_oauthlib import OAuth1Session
from urllib.parse import parse_qsl


class TwitterService(Service):
    def get_authorization_url(self, request, config, callback_url):
        oauth = OAuth1Session(
            config.consumer_key,
            client_secret=config.secret,
            callback_uri=callback_url,
        )
        oauth.fetch_request_token(config.request_token_url)
        return oauth.authorization_url(config.authorize_url)

    def get_user(self, request, config, callback_url):
        oauth_token = request.GET.get("oauth_token", None)
        oauth_verifier = request.GET.get("oauth_verifier", None)

        if oauth_token is None or oauth_verifier is None:
            raise ProviderAccessError("Not found parameter.")

        oauth = OAuth1Session(
            config.consumer_key,
            client_secret=config.secret,
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_verifier,
        )
        response = oauth.post(
            config.access_token_url, params={"oauth_verifier": oauth_verifier}
        )
        data = dict(parse_qsl(response.content.decode("utf-8")))
        uid = data["user_id"]
        display_name = data.get("screen_name")
        return User(uid, display_name, data)
