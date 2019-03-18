from .provider import AbstractOAuth2Provider, User
from ..exceptions import ProviderAccessError
import json


class FaceBookProvider(AbstractOAuth2Provider):
    def _get_user(self, session, data):
        uid = data["id"]
        display_name = data.get("name")
        return User(session, uid, display_name, data)

    def _create_session(self, request, callback_url):
        code = request.GET.get("code", None)
        if not code:
            raise ProviderAccessError("Not found code parameter.")
        service = self._get_service()
        params = {"code": code, "redirect_uri": callback_url}
        return service.get_auth_session(data=params, decoder=json.loads)
