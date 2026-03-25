def bdecode(data, idx=0):
    t = data[idx:idx+1]
    if t == b'd':
        idx += 1; d = {}
        while data[idx:idx+1] != b'e':
            k, idx = bdecode(data, idx)
            v, idx = bdecode(data, idx)
            d[k] = v
        return d, idx + 1
    elif t == b'l':
        idx += 1; lst = []
        while data[idx:idx+1] != b'e':
            v, idx = bdecode(data, idx)
            lst.append(v)
        return lst, idx + 1
    elif t == b'i':
        end = data.index(b'e', idx)
        return int(data[idx+1:end]), end + 1
    else:
        colon = data.index(b':', idx)
        n     = int(data[idx:colon])
        start = colon + 1
        return data[start:start+n], start + n
