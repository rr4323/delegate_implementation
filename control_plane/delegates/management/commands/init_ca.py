from django.core.management.base import BaseCommand

from delegates import ca


class Command(BaseCommand):
    help = ("Generates the root CA (if absent), the control plane server certificate, and the "
            "Redis server + control-plane admin client certificates.")

    def handle(self, *args, **options):
        ca.ensure_root_ca()
        ca.ensure_control_plane_server_cert()
        ca.ensure_redis_server_cert()
        ca.ensure_redis_admin_client_cert()
        self.stdout.write(self.style.SUCCESS("CA, control plane and Redis certificates ready."))
