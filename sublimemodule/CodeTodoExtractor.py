import re

class CodeTodoExtractor:
    def __init__(self, lines):
        self.lines = lines
        self.todos = []

        print('initializing code to extractor...')

    def get_todos(self):

        position = 0
        for lineno in range(len(self.lines)):
            # try:
            #     line_content = fd.next()
            # except StopIteration:
            #     break
            line = self.lines[lineno]
            if self.should_process(line):
                dic = {}
                dic['lineno'] = lineno
                dic['original_line'] = line
                dic['todo'] = self.extract_todo_text(line)
                dic['context'] = self.extract_context(lineno, 5)
                dic['position'] = position
                self.todos.append(dic)

            position += len(line) + 1

        return self.todos

    def should_process(self, line):
        if self.is_comment(line):
            if self.is_todo(line):
                if self.is_already_task(line) == False:
                    return True
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

    def is_already_task(self, line):
        m = re.search('www.producteev.com\\/', line)
        if m:
            return True

        return False

    def extract_context(self, lineno, size = 5):
        context = {}
        maximum = len(self.lines)
        start = (lineno - size) if (lineno - size >= 0) else 0
        end = (lineno + size + 1) if (lineno + size + 1 <= maximum) else maximum
        context['before'] = self.lines[start:lineno]
        context['after'] = self.lines[lineno + 1:end]

        return context