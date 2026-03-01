from django.apps import AppConfig


class BaseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'base'

    def ready(self):
        from . import signals
        from django.contrib import admin
        from .admin import CustomAdminSite
        admin.site.__class__ = CustomAdminSite

