import hashlib


def proofofwork(prefix):
    i = 0
    while True:
        hashed = hashlib.sha256((prefix+str(i)).encode()).hexdigest()
        if hashed.startswith('000000'):
            return i, hashed
        i += 1


if __name__ == '__main__':
    prefix = input("Prefix: ")
    ans, hashed = proofofwork(prefix)
    print("Hash:", hashed)
    print("Input:", ans)
