from .base import *
from decouple import config

DEBUG=config('DEBUG')

ALLOWED_HOSTS=config('ALLOWED_HOSTS').split(',')
