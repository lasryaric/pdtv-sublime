import re

class CodeTodoExtractor:
    def __init__(self):
        print('initializing code to extractor...')

    def find_next(self, fd):

        while True:
            try:
                line_content = fd.next()
            except StopIteration:
                break
            result = self.analyze_line(line_content)
            if 'new' == result:
                return self.extract_todo_text(line_content)

        return False


    def analyze_line(self, line):
        if self.is_comment(line):
            if self.is_todo(line):
                idTask = self.extract_id_task(line)
                if idTask != False :
                    return idTask
                else:
                    return 'new'
        return False

    def is_comment(self, line):
        m = re.search('//|\\*', line)
        if m:
            return True;

        return False;

    def extract_id_task(self, line):
        return False

    def is_todo(self, line):
        m = re.search('\\@todo', line)
        if m:
            return True;

        return False;

    def extract_todo_text(self, line):
        m = re.search('\\@todo (.*)', line)
        if m:
            return m.group(1)

