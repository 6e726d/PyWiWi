import sys

#: True if Python 2 intepreter is used
PY2 = sys.version_info[0] == 2
PY3 = not PY2


try:
    iteritems = dict.iteritems
except AttributeError:
    iteritems = dict.items
