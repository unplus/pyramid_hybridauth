def includeme(config):
    config.add_route("home", "/")
    config.add_route('popup', '/popup/{provider}')
    config.add_route('release', '/release/{provider}')
    config.add_route('logout', '/logout')

    config.include("pyramid_jinja2")
    config.add_jinja2_renderer(".html")
    config.add_jinja2_search_path("example:templates", name=".html")
