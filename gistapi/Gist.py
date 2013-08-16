import requests;
import json;
import httplib
import urllib
import re
import os.path

class Gist:

    def create(self, filename, content):
        payload = {
            "description": "file",
            "public" : "true",
            "files": {
                filename:{
                    "content": "a" * 100000
                }
            }
        }
        files = {'file': ('report.csv', 'some,data,to,send\nanother,row,to,send\n')}
        url = 'https://api.github.com/gists'
        url = 'http://localhost:81/abc'

        headers = {'Content-type': 'application/json'}
        r = requests.post(url, data=json.dumps(payload), headers=headers)

        print(r.status_code)
        print(r.text)
        if r.status_code == 201:
            return json.loads(r.text)

