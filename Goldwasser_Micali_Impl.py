import random

def IsPrime(n, s = 50): # Miller-Rabin-Primzahltest
  # Aufruf: IsPrime(n,s) mit natuerlichen Zahlen n,s
  # Ausgabe: True oder False
  #     n prim => Ausgabe True mit Wkt. 1
  #     n nicht prim => Ausgabe True mit Wkt. <= 1/(2**s)
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

def gcd(a,b): # groesster gemeinsamer Teiler
  # Aufruf: gcd(a,b) mit natuerlichen Zahlen a,b>0
  # Ausgabe: groesster gemeinsamer Teiler von a und b
  return egcd(a,b)[0]

def ModExp(x,y,n): # Exponentialfunktion mod n
  # Aufruf: ModExp(x,y,n) mit natuerlichen Zahlen x,y,n und n>=2
  # Ausgabe: (x**y)%n
  z=i=1
  p=x%n
  while(i<=y):      # Invariante: p = (x^i)%n
    if i&y > 0:
      z = (z*p)%n
    i=i+i
    p=(p*p)%n
  return z

########################################################
########################################################
########################################################

def IsQuadraticResidue(x,p,q):    # testet, ob x quadratischer Rest mod p*q ist
  # Aufruf: IsQuadraticResidue(x,p,q) mit Primzahlen p,q und
  #         x aus {1,...,p*q-1} mit ggT(x,p*q)=1
  # Ausgabe: True, falls es ein a aus {1,...,p*q-1} gibt mit a*a=x (mod p*q)
  #          False, sonst
  for i in range (1, (p * q) - 1):
      if ((i * i) % (p * q) == x):
          return True
  return False

def GMKeyGen(l=512):    # Schluesselgenerator fuer Goldwasser-Micali-Kryptosystem
  # Aufruf: GMKeyGen(l) mit natuerlicher Zahl l>2
  # Ausgabe: (n,(p,q)) mit n aus [2**(l-1),2**l] und n = p*q fuer
  #          zufaellige, verschiedene Primzahlen p,q aus [2,2**((l+1)//2)] mit p%4=q%4=3
  p = q = 2
  while not IsPrime(p) and not (p % 4 == 3):
    p = random.randint(2, 2**((l+1)//2))
  while not IsPrime(q) and  not (q % 4 == 3):
    q = random.randint(2, 2**((l+1)//2))
  n = p * q
  return (n,(p,q))

def GMEncryptBit(pk,b): # Verschluesselung fuer Goldwasser-Micali-Kryptosystem
  # Aufruf: GMEncrypt(pk,b) mit public key pk und Klartextbit b
  # Ausgabe: Chiffretext c = (r*r*((n-1)**b)) % pk
  #          fuer Zufallszahl r aus {1,...,pk-1} mit ggT(r,pk)=1 
  r = random.randint(1, pk)  
  while gcd(r,pk) != 1:
    r = random.randint(1, pk) # da rechte range exclusive

  return ((r * r * ((pk - 1) ** b)) % pk)

def GMDecryptBit(sk,c): # Entschluesselung fuer Goldwasser-Micali-Kryptosystem
  # Aufruf: GMDecrypt(sk,c) mit secure key sk und chiffriertes Bit c
  # Ausgabe: dechiffriertes Bit
  #     0 falls c quadratischer Rest mod pk ist
  #     1 falls c kein quadratischer Rest mod pk ist
  if IsQuadraticResidue(c, sk[0], sk[1]):
    return 0
  else:
    return 1

########################################################
########################################################
########################################################

def GMTest():   # Test fuer Goldwasser-Micali-Kryptosystem
  pt=1234
  print("Klartext in Dezimaldarstellung: "+str(pt))
  print("Klartext in Binaerdarstellung: "+bin(pt))
  print()
  (pk,sk)=GMKeyGen(256)
  print("Public Key: "+str(pk))
  print("Private Key: "+str(sk))
  print()
  ptl=[int(bin(pt)[i]) for i in range(2,len(bin(pt)))]   # Liste der Klartextbits
  print("Klartextbits | Chiffretexte der Bits")
  print("-------------+----------------------")
  ctl=[]
  for i in range(0,len(ptl)):
    ptb=ptl[i]              # Klartextbit
    ctb=GMEncryptBit(pk,ptb)   # Chiffretext des Bits
    ctl+=[ctb]
    print("      "+str(ptl[i])+"      | "+str(ctb))
  print()
  encrypted=""
  for i in range(0,len(ctl)):
    encrypted+=str(GMDecryptBit(sk,ctl[i]))
  print("entschluesselter Chiffretext in Binaerdarstellung: 0b"+encrypted)
  print("entschluesselter Chiffretext in Dezimaldarstellung: "+str(int(encrypted,2)))
  return