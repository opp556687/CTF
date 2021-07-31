class RNG:

    def __init__(self, flag: bytes, rec: list[int]):
        if len(flag) != 64:
            raise ValueError('flag has incorrect length')
        if len(rec) != 64:
            raise ValueError('recurrence has incorrect length')
        if rec[0] % 2 == 0:
            raise ValueError('the first term of recurrence should be odd')
        self.state = flag
        self.recurrence = rec

    def get_byte(self) -> int:
        byte = 0
        for i in range(64):
            byte = (byte + self.state[i] * self.recurrence[i]) % 256
        self.state = self.state[1:] + bytes([byte])
        return byte
