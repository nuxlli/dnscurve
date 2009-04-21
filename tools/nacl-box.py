import sys

try:
  import nacl
except ImportError:
  import slownacl as nacl
import netstring

def main():
  sk = netstring.read(sys.stdin)
  pk = netstring.read(sys.stdin)
  nonce = netstring.read(sys.stdin)
  packet = sys.stdin.read()

  netstring.write(sys.stdout, nacl.box_curve25519xsalsa20poly1305(packet, nonce, pk, sk))

if __name__ == '__main__':
  main()
