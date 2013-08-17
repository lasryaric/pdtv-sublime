
from sublimemodule.CodeTodoExtractor import CodeTodoExtractor
from gistapi.Gist import Gist
from producteevapi.Task import Task

access_token = 'tnt8Cq-3edVU96JwiBAIlxfYP6AJav5GBDs91gTNYJs'
project_id = '520dbc68039555cc10000014'

# fd = open('test.php', 'r+')
fname = 'test.php'
with open(fname) as fd:
    lines = fd.readlines()
'''
next_todo = cte.find_next(lines)
task = Task()
while False != next_todo:
    taskObject = task.create(next_todo, project_id, access_token)
    print(taskObject['task']['title'])
    # fd.write('old todo....');
    next_todo = cte.find_next(lines)
'''
cte = CodeTodoExtractor(lines)
task = Task()
gist = Gist()
for todo in cte.get_todos():
    task_title = todo['todo'] + " (in "+ fname + ")"
    taskObject = task.create(task_title, project_id, access_token)
    noteMessage = string.join(todo['context']['before']) + todo['original_line'] + string.join(todo['context']['after'])
    fileObject = task.uploadFile(fname, access_token)
    task.createNote(noteMessage, taskObject['task']['id'], access_token, fileObject['file']['id'])
    print(fileObject)