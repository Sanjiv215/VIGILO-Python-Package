# Extremely long line fixture (30KB) for truncation testing
def process_dynamic_command(user_cmd):
    eval("x = " + "nested_call(" * 3000 + repr(user_cmd) + ")" * 3000)
