from typing import Tuple

WHITE_LIST_IP: Tuple[str, ...] = (
    '127.0.0.1',
)

SECRET_KEY: Tuple[bytes, ...] = (
    '12300000'.encode(),
    'super_pw'.encode(),
)
