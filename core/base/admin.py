from django.contrib import admin
from django.apps import apps
from django.urls import path
from .views import TraceNetworkView, RunProcessView, StopProcessView, stop_program, start_program


# custom admin listings
class ListAdminMixin(admin.ModelAdmin):
    def __init__(self, model, admin_site):
        self.list_display = [
            field.name for field in model._meta.fields if field.name not in ["slug", "password"]
        ]
        self.readonly_fields = [
            field.name
            for field in model._meta.fields
            if field.name in ["slug", "id", "password"]
        ]
        super().__init__(model, admin_site)


def register_models(*, app_name: str):
    app_models = apps.get_app_config(app_name).get_models()

    # Register models using the mixin
    for model in app_models:
        admin_class = type(f"{model.__name__}Admin", (ListAdminMixin,), {})
        try:
            admin.site.register(model, admin_class)
        except admin.sites.AlreadyRegistered:
            pass


register_models(app_name="base")


# adding page in sidepanel - global, index
class CustomAdminSite(admin.AdminSite):
    def get_app_list(self, request, app_label=None):
        app_list = super().get_app_list(request, app_label)
        app_list += [
            {
                'name': 'Trace Network',
                'app_label': 'TraceNetwork',
                'app_url': '#',
                'has_module_perms': True,
                'models': [
                    {
                        'name': 'Trace Network',
                        'object_name': 'TraceNetwork',
                        'admin_url': '/trace-network/',
                        'view_only': True,
                        'perms': {'view': True},
                    }
                ],
            }
        ]
        return app_list


admin.site.__class__ = CustomAdminSite

# custom added page urls
original_get_urls = admin.site.__class__.get_urls


def get_urls(self):
    custom_urls = [
        path('trace-network/', self.admin_view(TraceNetworkView.as_view())),
        path('run-process/', self.admin_view(RunProcessView.as_view())),
        path('stop-process/', self.admin_view(StopProcessView.as_view())),
        path("start/", start_program, name="start"),
        path("stop/", stop_program, name="stop"),

    ]
    return custom_urls + original_get_urls(self)


admin.site.__class__.get_urls = get_urls
