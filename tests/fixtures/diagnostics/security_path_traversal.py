def read_user_file(user_path):
    with open(user_path, "r") as f:
        return f.read()
