from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class AuthConfig(AppConfig):
    name = 'mandala.auth'
    verbose_name = _("Authentication and Authorization")