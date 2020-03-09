from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
from os import urandom
from io import BytesIO, SEEK_CUR

keyBase64 = 'qmB0kWPV+THEgfi3e2D8C1/SQbjoN+bIe3+s3Ftkvsg='
blockSize = 128
ivSize = 16
key1 = b64decode(keyBase64)
backend = default_backend()
pkcs7 = PKCS7(blockSize)


def decrypt():
    with open('temp', 'rb') as f:
        iv = f.read(ivSize)
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=iv,
            iterations=1000,
            backend=backend)
        key2 = kdf.derive(key1)
        cipher = Cipher(AES(key2), CBC(iv), backend)
        decryptor = cipher.decryptor()
        unpadder = pkcs7.unpadder()
        data = BytesIO()
        data.write(unpadder.update(decryptor.update(f.read())))
        data.write(unpadder.update(decryptor.finalize()))
        data.write(unpadder.finalize())
        return data.getvalue()


def encrypt(message: bytes):
    iv = urandom(ivSize)
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=iv,
        iterations=1000,
        backend=backend)
    key2 = kdf.derive(key1)
    cipher = Cipher(AES(key2), CBC(iv), backend)
    encryptor = cipher.encryptor()
    padder = pkcs7.padder()
    with open('temp', 'wb') as f:
        f.write(iv)
        f.write(encryptor.update(padder.update(message) + padder.finalize()))
        f.write(encryptor.finalize())


if __name__ == '__main__':
    # encrypt(b'hello world asdjfasdkf lksdjflkdsjfl asdfdasf')
    decrypt()
