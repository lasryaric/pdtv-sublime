import sublime, sublime_plugin
import string
import sys
import threading

sys.path.append('/Users/aric.lasry/Desktop/pdtv-sublime/')
sys.path.append('/Library/Python/2.7/site-packages/requests-1.2.0-py2.7.egg/')

from producteevapi.Task import Task
from sublimemodule.CodeTodoExtractor import CodeTodoExtractor

'''
* @todo ramin YEAH? https://www.producteev.com/workspace/t/520eba92532aa6794200000f
'''

class ExampleCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        access_token = 'tnt8Cq-3edVU96JwiBAIlxfYP6AJav5GBDs91gTNYJs'
        project_id = '520dbc68039555cc10000014'
        fname = self.view.file_name()
        sample = self.view.substr(sublime.Region(0, self.view.size()))
        lines = sample.split('\n')
        cte = CodeTodoExtractor(lines)
        task = Task()
        positionPadding = 0;
        for todo in cte.get_todos():
            task_title = todo['todo'] + " (in "+ fname + ")"
            taskObject = task.create(task_title, project_id, access_token)
            noteMessage = string.join(todo['context']['before'], '\n') + '\n' + todo['original_line'] + '\n' + string.join(todo['context']['after'], '\n')
            fileObject = task.uploadFile(fname, access_token)
            task.createNote(noteMessage, taskObject['task']['id'], access_token, fileObject['file']['id'])
            position = todo['position'] + len(todo['original_line']) + positionPadding
            task_url_text = " https://www.producteev.com/workspace/t/"+taskObject['task']['id'];
            positionPadding += len(task_url_text)
            self.view.insert(edit, position, task_url_text)


