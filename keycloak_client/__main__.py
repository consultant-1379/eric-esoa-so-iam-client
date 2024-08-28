""""Main module for the keycloak_client package"""
import logging
import sys
from .scripts.keycloak_cli import main

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
                    datefmt='%m-%d-%Y %I:%M:%S')
sys.exit(main())
