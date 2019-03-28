from . import Service, User
from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix


class FaceBookService(Service):
    def get_authorization_url(self, request, config, callback_url):
        oauth = OAuth2Session(
            config.client_id, scope=config.scope, redirect_uri=callback_url
        )
        oauth = facebook_compliance_fix(oauth)
        authorization_url, _ = oauth.authorization_url(config.authorize_url)
        return authorization_url

    def get_user(self, request, config, callback_url):
        oauth = OAuth2Session(
            config.client_id, scope=config.scope, redirect_uri=callback_url
        )
        oauth = facebook_compliance_fix(oauth)
        oauth.fetch_token(
            config.access_token_url,
            client_secret=config.secret,
            authorization_response=request.url,
        )
        response = oauth.get(config.request_url)
        data = response.json()
        uid = data["id"]
        display_name = data.get("name")
        return User(uid, display_name, data)
