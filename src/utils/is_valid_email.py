import re


def is_valid_email(email: str) -> bool:
    """Checks if a give string is a valid email adress using RFC 5322 Official Standard Regex"""

    regex = r"""(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"""

    return True if re.fullmatch(regex, email) else False
