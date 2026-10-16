# نقطة الدخول لاستضافة cPanel (Setup Python App / Passenger) وأي خادم WSGI.
# Application startup file: passenger_wsgi.py   |   Application entry point: application
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import application  # noqa: E402,F401
