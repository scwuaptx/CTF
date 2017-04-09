# dump pyc
# then decode the flag.enc

def encode(data):
    res = ''
    for b in data:
        res += chr((ord(b) & 15) << 4 | (ord(b) & 240) >> 4)
    return res


def decode(data):
    res = ''
    for b in data :
	res += chr((ord(b) >> 4) & 15 | (ord(b) << 4) & 240 )
    return res


f = open('./flag.enc', 'r')
out = open('flag.png','w')
data = f.read()
out.write(decode(data))
