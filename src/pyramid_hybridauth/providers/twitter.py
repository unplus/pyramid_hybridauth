from .provider import AbstractOAuth1Provider, User


class TwitterProvider(AbstractOAuth1Provider):
    def _get_user(self, session, data):
        uid = data["user_id"]
        display_name = data.get("screen_name")
        return User(session, uid, display_name, data)
