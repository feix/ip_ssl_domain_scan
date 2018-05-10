#!/usr/bin/env python3

import sys

from gunicorn.app.wsgiapp import run

if __name__ == '__main__':
    sys.argv = ['--reload', 'app:api']
    sys.exit(run())