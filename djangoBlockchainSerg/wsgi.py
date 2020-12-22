# S.Melchakov
# Blockchain (final assignment)
# December 2020
# https://github.com/salozher/djangoBlockchainSerg


import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoBlockchainSerg.settings')

application = get_wsgi_application()
