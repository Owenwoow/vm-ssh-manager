class VMSSHError(Exception):
    """Base error shown to end users."""


class ValidationError(VMSSHError):
    pass


class KeyErrorBase(VMSSHError):
    pass


class IncompleteKeyError(KeyErrorBase):
    pass


class KeyMismatchError(KeyErrorBase):
    pass


class HostKeyRejectedError(VMSSHError):
    pass


class ConfigConflictError(VMSSHError):
    pass


class OperationCancelled(VMSSHError):
    pass


class RemoteOperationError(VMSSHError):
    pass
