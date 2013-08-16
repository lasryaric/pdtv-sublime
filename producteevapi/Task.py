import requests;
import json;

class Task:
    def __init__(self):
        print('hey, this is task!');

    def create(self, title, projectId, access_token):

        payload = {
            'task': {
                'title': title,
                'project': projectId
            }
        }
        payload = {
            'task':{
                'title':title,
                'project': projectId,
            }
        }
        r = requests.post('https://www.producteev.com/api/tasks?access_token='+access_token, data=json.dumps(payload))
        print(r.status_code)
        if r.status_code == 201:
            return json.loads(r.text)