from django.contrib import admin
from django.urls import path
from base.views import RunProcessView, StopProcessView

urlpatterns = [
    path('', admin.site.urls),
    path('admin/run-process/', admin.site.admin_view(RunProcessView.as_view())),
    path('admin/stop-process/', admin.site.admin_view(StopProcessView.as_view())),
]







































