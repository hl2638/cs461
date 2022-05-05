import sys
import urllib.parse
from pymd5 import md5, padding
if len(sys.argv) > 3:
    fname_qry = sys.argv[1]
    fname_cmd = sys.argv[2]
    fname_out = sys.argv[3]
else:
    fname_qry = '3.2.1_query.txt'
    fname_cmd = '3.2.1_command3.txt'
    fname_out = 'sol_3.2.1.txt'

with open(fname_qry) as f_qry:
    query = f_qry.read().strip()
    splitted = query.split('&')
    token = splitted[0][6:]
    remain_query = '&'.join(splitted[1:])

with open(fname_cmd) as f_cmd:
    new_cmd = f_cmd.read().strip()

len_msg = len(remain_query)+8
count = (len_msg + len(padding(len_msg*8)))*8

h = md5(state=token, count=count)
h.update(new_cmd)

new_token = h.hexdigest()

new_query = 'token=' + new_token + '&' + remain_query + urllib.parse.quote_from_bytes(padding(len_msg*8)) + new_cmd

with open(fname_out, 'w') as f_out:
    f_out.write(new_query)