"""
WSGI config for gettingstarted project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/howto/deployment/wsgi/
"""

from gevent import monkey
monkey.patch_all()

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "MainConfig.settings")

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()

