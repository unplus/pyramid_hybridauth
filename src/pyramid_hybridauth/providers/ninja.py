from .provider import AbstractOAuth2Provider, User


class NinjaProvider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data["id"]
        display_name = data.get("nickname")
        return User(session, uid, display_name, data)
