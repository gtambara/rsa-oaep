"""
Integer to byte of length 'xLen' representation of 'x'
"""
def i2osp(x: int, xLen: int) -> bytes:
    return x.to_bytes(xLen, byteorder='big')

"""
Byte to integer representation of 'newX'
"""
def os2ip(newX: bytes) -> int:
    return int.from_bytes(newX, byteorder='big')

#print(i2osp(2,4))
#print(os2ip(i2osp(2,4)))
