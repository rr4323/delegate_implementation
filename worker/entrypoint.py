"""Container entrypoint for the Celery worker (the `bp-agent` stand-in):
register once (or reuse an existing identity across restarts), then run the
Celery worker. Restarts are not handled in-process: the co-located
`agent_manager` receives RESTART from the control plane and restarts this
delegate from the outside.
"""
import os

from worker_app.registration import register


def main():
    identity = register(
        control_plane_url=os.environ.get("CONTROL_PLANE_URL", "http://control_plane:8000"),
        tenant_id=os.environ["TENANT_ID"],
        name=os.environ.get("DELEGATE_NAME", "delegate"),
        queue=os.environ.get("DELEGATE_QUEUE", "default"),
        concurrency=int(os.environ.get("DELEGATE_CONCURRENCY", "1")),
    )

    from worker_app.celery_app import app

    app.worker_main([
        "worker",
        "--loglevel=INFO",
        "-Q", identity["queue"],
        "-n", f"{identity['name']}@%h",
        "--concurrency=2",
        # Match worker_enable_remote_control=False in celery_app.py: these
        # features use pub/sub and broadcast keys a delegate's Redis ACL
        # user is not (and should not be) allowed to touch.
        "--without-mingle", "--without-gossip", "--without-heartbeat",
    ])


if __name__ == "__main__":
    main()
