from django.urls import path

from . import views

urlpatterns = [
    path("registration-token/", views.issue_registration_token),
    path("register/", views.register_delegate),
    path("delegates/<uuid:delegate_id>/revoke/", views.revoke_delegate),
    path("executions/", views.create_execution),
    path("executions/<uuid:execution_id>/", views.execution_status),
    path("audit-events/", views.list_audit_events),
]
