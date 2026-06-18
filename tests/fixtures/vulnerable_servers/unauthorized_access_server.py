# R004: open() with user input without path validation
def read_user_file(path: str) -> str:
    return open(path).read()  # no resolve/is_relative_to check
