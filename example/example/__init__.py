from pyramid.config import Configurator
from pyramid.security import Allow, Everyone


class RootFactory:
    __acl__ = [(Allow, Everyone, "everyone"), (Allow, "group:users", "user")]

    def __init__(self, request):
        pass


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    with Configurator(settings=settings, root_factory=RootFactory) as config:
        config.include(".auth")
        config.include(".routes")
        config.scan()
    return config.make_wsgi_app()
