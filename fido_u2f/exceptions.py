

class U2FException(Exception):
    pass


class U2FStateException(U2FException):
    """Raised when the system's state is incorrect for the desired action."""
    pass


class U2FInvalidDataException(U2FException):
    """
    Raised when data given by the caller is not valid; or fails verification.
    """
    pass
