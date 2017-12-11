import random

def IsPrime(n, s = 50): # Miller-Rabin-Primzahltest
  # Aufruf: IsPrime(n,s) mit natuerlichen Zahlen n,s
  # Ausgabe: True oder False
  #     n prim => Ausgabe True mit Wkt. 1
  #     n nicht prim => Ausgabe True mit Wkt. <= 1/(2**s)
  # Laufzeit bei Eingabe (n,s): O(s * |n|**2)
  if n < 2: return False
  for j in range(1, s + 1):
    a = random.randint(1, n - 1)
    i = n - 1
    b = []
    while (i > 0):
      b.append(i % 2)
      i = i // 2
    d = 1
    for i in range(len(b) - 1, -1, -1):
      x = d
      d = (d * d) % n
      if d == 1 and x != 1 and x != n - 1:
        return False
      if b[i] == 1:
        d = (d * a) % n
    if d != 1:
      return False
  return True

def egcd(ld,d): # erweiterter Euklidischer Algorithmus
  # Aufruf: egcd(a,b) mit natuerlichen Zahlen a,b>0
  # Ausgabe: (d,x,y) mit:
  #     d ist groesster gemeinsamer Teiler von a und b
  #     x,y sind ganze Zahlen mit d = x*a + y*b
  (lx,x) = (1,0)
  (ly,y) = (0,1)
  while d != 0:
    q = ld//d
    (d,ld) = (ld%d,d)
    (x,lx) = (lx-q*x,x)
    (y,ly) = (ly-q*y,y)       
  return (ld,lx,ly)

def ModInv(e,n): # Inverses mod n
  # Aufruf: ModInv(e,n) mit natuerlichen Zahlen e,n>0 und ggT(e,n)=1
  # Ausgabe: d aus {1,...,n-1} mit (d*e)%n = 1
  (ggTVal, x, y) = egcd(e,n)
  return (x % n)

def ModExp(x,y,n): # Exponentialfunktion mod n
  # Aufruf: ModExp(x,y,n) mit natuerlichen Zahlen x,y,n und n>=2
  # Ausgabe: z = (x**y)%n
  z = i = 1
  p = x % n
  while (i <= y):
      if (i & y) > 0:
        z = (z * p) % n
      i = i + i
      p = (p * p) % n
  return z

def RSAKeyGen(r=1024):
  # Aufruf: RSAKeyGen(r) mit natuerlicher Zahl r>=5
  # Ausgabe: ((n,e),(n,d)) mit
  #     n = p*q fuer zufaellige Primzahlen p,q mit p!=q und
  #         p,q aus [2**l,2**(l+1)), wobei l = (r+2)//2
  #     e = zufaellige Zahl mit 1<e<phi(n) und ggT(e,phi(n))=1
  #     d = Inverses von e modulo phi(n),
  #         d.h. 1<d<phi(n) mit der Eigenschaft (e*d) % phi(n) = 1
  #
  l = (r+2)//2
  while True:
      q = random.randint(2**l, 2**(l+1))
      if (IsPrime(q)):
          break

  while True:
      p = random.randint(2**l, 2**(l+1))
      if (IsPrime(p) and p != q):
          break
  phi = (p - 1) * (q - 1)

  while True:
      e = random.randint(2, phi)
      (ggTVal, x, y) = egcd(e, phi)
      if (ggTVal == 1):
          break
  
  n = p * q
  d = ModInv(e, phi)
  # Hinweis: Der Befehl random.randint(a,b) liefert eine
  #          gleichverteilt zufaellige Zahl aus {a,a+1,...,b}.
  
  return ((n,e),(n,d))

def RSAEncrypt(pk,m):
  # Aufruf: RSAEncrypt(pk,m) mit public key pk und Klartext m
  # Ausgabe: Chiffretext c
  (n, e) = pk
  c = ModExp(m, e, n)
  return c

def RSADecrypt(sk,c):
  # Aufruf: RSADecrypt(sk,c) mit secure key sk und Chiffretext c
  # Ausgabe: dechiffrierte Nachricht m
  (n, d) = sk
  m = ModExp(c, d, n)
  return m

def str2int(s): # codiert einen String als Zahl (zum Testen von RSA)
  # Aufruf: str2int('Das ist ein Test.')
  # Ausgabe: 23268733837745479405720608239248647353390
  x = 0
  for i in range(0,len(s)):
    x = (x<<8) + ord(s[i])
  return x

def int2str(x): # codiert eine Zahl als String (zum Testen von RSA)
  # Aufruf: int2str(23268733837745479405720608239248647353390)
  # Ausgabe: 'Test'
  s = ''
  while(x>0):
    s = chr(x&255) + s
    x = x >> 8
  return s

def RSATest():
  ms = 'Test'
  m=str2int(ms)
  print("Klartext als String:      "+ms)
  print("Klartext als Zahl:        "+str(m))
  r = len(bin(m))-2                 # Laenge des Klartexts bestimmen
  (pk,sk)=RSAKeyGen(r)
  (n,e)=pk
  (n,d)=sk
  print("n =                       "+str(n))
  print("e =                       "+str(e))
  print("d =                       "+str(d))
  c=RSAEncrypt(pk,m)
  cs=int2str(c)
  print("Chiffretext als Zahl:     "+str(c))
  b=RSADecrypt(sk,c)
  bs=int2str(b) 
  print("entschl. Text als String: "+bs)
  print("entschl. Text als Zahl:   "+str(b))
  return
