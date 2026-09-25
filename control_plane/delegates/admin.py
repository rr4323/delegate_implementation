from django.contrib import admin

from .models import AuditEvent, Delegate, Execution, ExecutionLog, RegistrationToken

admin.site.register(RegistrationToken)
admin.site.register(Delegate)
admin.site.register(Execution)
admin.site.register(ExecutionLog)
admin.site.register(AuditEvent)
