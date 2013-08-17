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
        r = requests.post('https://www.producteev.com/api/tasks?access_token='+access_token, data=json.dumps(payload))
        print(r.status_code)
        print(r.text)
        if r.status_code == 201:
            return json.loads(r.text)

    def createNote(self, message, task_id, access_token, file_id = None):

        payload = {
            'note': {
                'message': message,
                'task': task_id,

            }
        }
        if file_id != None:
            payload['note']['files'] = [
            {
                'id':file_id
            }
            ];
        r = requests.post('https://www.producteev.com/api/notes?access_token='+access_token, data=json.dumps(payload))
        #print(r.status_code)
        # print(r.text)
        if r.status_code == 201:
            return json.loads(r.text)

    def uploadFile(self, fullpath, access_token):
        files = {'file': open(fullpath, 'rb')}
        url = 'https://www.producteev.com/api/upload/files?access_token='+access_token
        r = requests.post(url, files=files)
        #print(r.text)
        if r.status_code == 201:
            return json.loads(r.text)