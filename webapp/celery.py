from __future__ import absolute_import, unicode_literals
import os
from celery import Celery, shared_task, Task, task
# from celery import shared_task, signature, task
from celery.signals import task_failure
from celery.decorators import periodic_task
from celery.task.control import inspect
from celery.task.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MainConfig.settings') # mayb redundat w/ manage.py
app = Celery('celery_app') # note - as celery_app in init.py
app.config_from_object('django.conf:settings', namespace='CELERY')


app.autodiscover_tasks() # Load task modules from all registered Django app configs.


if bool(os.environ.get('worker.1', False)):
    print('worker 1 running')
    from django.conf import settings
    import rollbar
    rollbar.init(**settings.ROLLBAR)

    def celery_base_data_hook(request, data):
        data['framework'] = 'celery'

    rollbar.BASE_DATA_HOOK = celery_base_data_hook

    @task_failure.connect
    def handle_task_failure(**kw):
        rollbar.report_exc_info(extra_data=kw)

class BaseTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        print('{0!r} failed: {1!r}'.format(task_id, exc))

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
