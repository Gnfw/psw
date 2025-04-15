import sys
print("Python Path:", sys.executable)
print("Search Paths:", sys.path)

try:
    from Crypto.Random import get_random_bytes
    print("Success!")
except ImportError as e:
    print("FAILURE:", e)
    print("Installed packages:", [p for p in sys.modules.keys() if 'crypt' in p.lower()])
