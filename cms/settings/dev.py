from .base import *
#from decouple import config
import os

DEBUG=os.environ.get('DEBUG')
print("Running in Dev Environment")
