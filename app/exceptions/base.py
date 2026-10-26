class AppError(Exception):
    message: str = "Request could not be processed"

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)
