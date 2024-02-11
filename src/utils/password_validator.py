import re
from typing import Tuple


def is_password_valid(password: str) -> Tuple[bool, str]:
    is_valid = True
    error_msg = []

    # Check if password is at least 8 characters long
    if not re.match(r".{8,}", password):
        local_error_msg = "Password must be at least 8 characters long"
        is_valid = False
        error_msg.append(local_error_msg)

    # Check if password contains at least one digit
    if not re.search(r"[0-9]", password):
        local_error_msg = "Password must contain at least one digit"
        is_valid = False
        error_msg.append(local_error_msg)

    # Check if password contains at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        local_error_msg = "Password must contain at least one uppercase letter"
        is_valid = False
        error_msg.append(local_error_msg)

    # Check if password contains at least one lowercase letter
    if not re.search(r"[a-z]", password):
        local_error_msg = "Password must contain at least one lowercase letter"
        is_valid = False
        error_msg.append(local_error_msg)

    # Check if password contains at least one special character
    if not re.search(r"[^A-Za-z0-9]", password):
        local_error_msg = "Password must contain at least one special character"
        is_valid = False
        error_msg.append(local_error_msg)

    return is_valid, error_msg
