class TCPStream:

    def __init__(self):
        self.segments = {}  # seq -> bytes
        self.next_seq = None
        self.buffer = b""

    def add(self, seq, data):
        if not data:
            return
        if self.next_seq is None:
            self.next_seq = seq
        self.segments[seq] = data
        while self.next_seq in self.segments:
            chunk = self.segments.pop(self.next_seq)
            self.buffer += chunk
            self.next_seq += len(chunk)

    def peek(self, n):
        return self.buffer[:n] if len(self.buffer) >= n else None

    def read(self, n):
        if len(self.buffer) < n:
            return None
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def available(self):
        return len(self.buffer)
