import sublime, sublime_plugin
import os, commands, re, subprocess, sys


sys.path.append('/Users/aric.lasry/Desktop/pdtv-sublime/')
from sublimemodule.CodeTodoExtractor import CodeTodoExtractor
from producteevapi.Task import Task

class taskCreator(sublime_plugin.EventListener):

  def on_post_save(self, view):
    cte = CodeTodoExtractor()
    #task = Task()
    path = view.file_name()
    fd = open(path, 'r')
    print(1)

    # for line in fd:
    #     line_content = fd.next()
    #     result = cte.analyze_line(line)
    #     if result == "new":
    #         task_title = cte.extract_todo_text(line)
    #         task.create(task_title, project_id, access_token)


