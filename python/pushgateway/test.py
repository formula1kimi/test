#!/bin/python3
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from prometheus_client.exposition import basic_auth_handler
import random
import time
import datetime
import json
import os.path

"""
Job Name: paitc
flow_rate{instance, task="taskname | total" }: Guage
ceil{instance, task="taskname"}: Guage
est_bandwidth{instance}: Guage
ref_bandiwdth{instance}: Guage
"""
with open(os.path.expanduser("~/secret/paas-pushgw.json")) as fp:
    secret = json.load(fp)

job_name = "paitc"
gateway_addr = secret['url']
gateway_user = secret['user']
gateway_pass = secret['pass']

registry = CollectorRegistry() 
ceil_guage = Gauge('paitc_ceil', 'paitc ceil settings', ["task"], registry=registry)



def auth_handler(url, method, timeout, headers, data):
    username = gateway_user
    password = gateway_pass
    return basic_auth_handler(url, method, timeout, headers, data, username, password)

if __name__ == '__main__':
    for i in range(100):
        a = random.randint(1, 100)
        b = random.randint(100, 200)
        print(f"{datetime.datetime.now()}: a={a}, b={b}")
        ceil_guage.labels(task="a").set(a)
        ceil_guage.labels(task="b").set(b)
        ceil_guage.labels(task="total").set(a+b)
        grouping = {
            "instance": "12345678",
        }
        push_to_gateway(gateway_addr, job=job_name, grouping_key=grouping, registry=registry,
        handler=auth_handler) 
        time.sleep(30)
