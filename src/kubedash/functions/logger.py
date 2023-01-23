#!/usr/bin/env python3

import logging

FORMAT = '[%(asctime)s] %(name)s        %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)
logger = logging.getLogger('KubeDash')