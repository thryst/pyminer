import time
import json
import pprint
import hashlib
import struct
import re
import base64
import http.client as httplib  # Updated import
import sys
from multiprocessing import Process

ERR_SLEEP = 15
MAX_NONCE = 1000000  # Removed L suffix

settings = {}
pp = pprint.PrettyPrinter(indent=4)

class BitcoinRPC:
    OBJID = 1

    def __init__(self, host, port, username, password):
        authpair = f"{username}:{password}".encode()
        self.authhdr = "Basic " + base64.b64encode(authpair).decode()
        self.conn = httplib.HTTPConnection(host, port, timeout=30)
    
    def rpc(self, method, params=None):
        self.OBJID += 1
        obj = {'version': '1.1', 'method': method, 'id': self.OBJID, 'params': params or []}
        self.conn.request('POST', '/', json.dumps(obj),
                          {'Authorization': self.authhdr, 'Content-type': 'application/json'})

        resp = self.conn.getresponse()
        if resp is None:
            print("JSON-RPC: no response")
            return None

        body = resp.read()
        resp_obj = json.loads(body)
        if resp_obj is None:
            print("JSON-RPC: cannot JSON-decode body")
            return None
        if 'error' in resp_obj and resp_obj['error'] is not None:
            return resp_obj['error']
        if 'result' not in resp_obj:
            print("JSON-RPC: no result in object")
            return None

        return resp_obj['result']

    def getblockcount(self):
        return self.rpc('getblockcount')

    def getwork(self, data=None):
        return self.rpc('getwork', data)


def uint32(x):
    return x & 0xffffffff

def bytereverse(x):
    return uint32(((x << 24) | ((x << 8) & 0x00ff0000) |
                   ((x >> 8) & 0x0000ff00) | (x >> 24)))

def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack('@I', in_buf[i:i+4])[0]
        out_words.append(struct.pack('@I', bytereverse(word)))
    return b''.join(out_words)

def wordreverse(in_buf):
    out_words = [in_buf[i:i+4] for i in range(0, len(in_buf), 4)]
    out_words.reverse()
    return b''.join(out_words)

class Miner:
    def __init__(self, id):
        self.id = id
        self.max_nonce = MAX_NONCE

    def work(self, datastr, targetstr):
        static_data = bytes.fromhex(datastr)
        static_data = bufreverse(static_data)
        blk_hdr = static_data[:76]
        targetbin = bytes.fromhex(targetstr)[::-1]
        targetbin_str = targetbin.hex()
        target = int(targetbin_str, 16)
        static_hash = hashlib.sha256()
        static_hash.update(blk_hdr)
        
        for nonce in range(self.max_nonce):
            nonce_bin = struct.pack("<I", nonce)
            hash1_o = static_hash.copy()
            hash1_o.update(nonce_bin)
            hash1 = hash1_o.digest()
            hash_o = hashlib.sha256()
            hash_o.update(hash1)
            hash = hash_o.digest()
            
            if hash[-4:] != b'\x00\x00\x00\x00':
                continue
            
            hash = bufreverse(hash)
            hash = wordreverse(hash)
            hash_str = hash.hex()
            l = int(hash_str, 16)
            
            if l < target:
                print(time.asctime(), f"PROOF-OF-WORK found: {l:064x}")
                return nonce + 1, nonce_bin
            else:
                print(time.asctime(), f"PROOF-OF-WORK false positive {l:064x}")
        
        return nonce + 1, None

    def submit_work(self, rpc, original_data, nonce_bin):
        nonce_bin = bufreverse(nonce_bin)
        nonce = nonce_bin.hex()
        solution = original_data[:152] + nonce + original_data[160:256]
        param_arr = [solution]
        result = rpc.getwork(param_arr)
        print(time.asctime(), "--> Upstream RPC result:", result)

    def iterate(self, rpc):
        work = rpc.getwork()
        if work is None or 'data' not in work or 'target' not in work:
            time.sleep(ERR_SLEEP)
            return

        time_start = time.time()
        hashes_done, nonce_bin = self.work(work['data'], work['target'])
        time_end = time.time()
        time_diff = time_end - time_start

        self.max_nonce = int((hashes_done * settings['scantime']) / time_diff)
        self.max_nonce = min(self.max_nonce, 0xfffffffa)

        if settings['hashmeter']:
            print(f"HashMeter({self.id}): {hashes_done} hashes, {hashes_done / 1000.0 / time_diff:.2f} Khash/sec")

        if nonce_bin is not None:
            self.submit_work(rpc, work['data'], nonce_bin)

    def loop(self):
        rpc = BitcoinRPC(settings['host'], settings['port'], settings['rpcuser'], settings['rpcpass'])
        while True:
            self.iterate(rpc)


def miner_thread(id):
    miner = Miner(id)
    miner.loop()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: pyminer.py CONFIG-FILE")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        for line in f:
            if re.match('^\s*#', line):
                continue
            match = re.match('^(\w+)\s*=\s*(\S.*)$', line)
            if match:
                settings[match.group(1)] = match.group(2)
    
    settings['port'] = int(settings.get('port', 8332))
    settings['threads'] = int(settings.get('threads', 1))
    settings['hashmeter'] = int(settings.get('hashmeter', 0))
    settings['scantime'] = int(settings.get('scantime', 30))

    if 'rpcuser' not in settings or 'rpcpass' not in settings:
        print("Missing username and/or password in cfg file")
        sys.exit(1)

    thr_list = [Process(target=miner_thread, args=(i,)) for i in range(settings['threads'])]
    for thr in thr_list:
        thr.start()
        time.sleep(1)
    
    try:
        for thr in thr_list:
            thr.join()
    except KeyboardInterrupt:
        pass
    print(time.asctime(), "Miner Stops")
