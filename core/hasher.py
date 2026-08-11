import hashlib


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        data = file.read()
        sha256.update(data)

    return sha256.hexdigest()