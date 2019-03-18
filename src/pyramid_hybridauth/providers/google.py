from .provider import AbstractOAuth2Provider, User


class GoogleProvider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data["id"]
        display_name = data.get("name")
        return User(session, uid, display_name, data)
