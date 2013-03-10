from pyramid.config import Configurator


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('main', '/')
    config.add_route('hello', '/hello/{name}')
    config.add_route('check','/check')
    config.include('pyramid_beaker')
    config.scan()
    return config.make_wsgi_app()
