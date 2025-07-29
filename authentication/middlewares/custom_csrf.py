from django.middleware.csrf import CsrfViewMiddleware


class CustomCSRFMiddleware:
    """
    Middleware global qui applique la protection CSRF
    en déléguant à CsrfViewMiddleware de Django.

    Nécessite d'être ajouté dans settings.py dans MIDDLEWARE.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Instancie le middleware CSRF officiel avec get_response
        self.csrf_middleware = CsrfViewMiddleware(get_response)

    def __call__(self, request):
        # Appelle la chaîne de middleware/django views
        response = self.get_response(request)
        return response

    def process_view(self, request, callback, callback_args, callback_kwargs):
        # Délègue la vérification CSRF à CsrfViewMiddleware
        return self.csrf_middleware.process_view(
            request, callback, callback_args, callback_kwargs
        )
