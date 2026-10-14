def load_cert(path: str) -> bytes:
    with open(path, "rb") as bf:
        data = bf.read()

    return data
