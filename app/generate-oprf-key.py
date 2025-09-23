import base64
import pyoprf

print(base64.urlsafe_b64encode(pyoprf.keygen()).decode('ascii'))
