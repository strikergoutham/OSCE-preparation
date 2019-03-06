#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
from boofuzz import *
def main():
    session = Session(target=Target(connection=SocketConnection("192.168.0.101", 21, proto='tcp')))
    s_initialize("user")
    s_string("USER",fuzzable=False)
    s_delim(" ",fuzzable=False,name='delimiter1')
    s_string("anonymous",fuzzable=False)
    s_static("\r\n")
    s_initialize("pass")
    s_string("PASS")
    s_delim(" ",fuzzable=False,name='delimiter2')
    s_static("\x2c")
    s_string("PaWn",fuzzable=True,name='fuzzing_variable_pass')
    s_static("\r\n")
    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.fuzz()
if __name__ == "__main__":
    main()
