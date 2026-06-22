# coding: utf-8
import json
from security_monitor_main import security_monitor_main

if __name__ == '__main__':
    print(json.dumps(security_monitor_main().scan(), indent=2))
