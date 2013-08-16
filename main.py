from producteevapi.Task import Task
from sublimemodule.CodeTodoExtractor import CodeTodoExtractor

access_token = 'tnt8Cq-3edVU96JwiBAIlxfYP6AJav5GBDs91gTNYJs'
project_id = '520dbc68039555cc10000014'

fd = open('test.php', 'r+')
cte = CodeTodoExtractor()
next_todo = cte.find_next(fd)
task = Task()
while False != next_todo:
    taskObject = task.create(next_todo, project_id, access_token)
    print(taskObject['task']['title'])
    fd.write('old todo....');
    next_todo = cte.find_next(fd)
