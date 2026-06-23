"""Control plugins.

Each module in this package implements exactly one CIS control and registers itself with
``@control(...)`` at import time. The engine discovers everything here automatically — adding
a control means dropping a new module in this directory, nothing else.
"""
