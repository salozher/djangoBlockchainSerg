# S.Melchakov
# Blockchain (final assignment)
# December 2020
# https://github.com/salozher/djangoBlockchainSerg


import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoBlockchainSerg.settings')

application = get_asgi_application()
