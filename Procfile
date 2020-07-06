web: newrelic-admin run-program gunicorn MainConfig.wsgi --log-file -
worker: celery -A webapp worker --loglevel=info