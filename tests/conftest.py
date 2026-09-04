import os

os.environ.setdefault("JWT_SECRET", "unit-test-" + ("x" * 32))
