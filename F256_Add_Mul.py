def F256Add(x,y):
    return x ^ y

def F256Mul(x,y):
    p = 0             # zuerst Produkt der Polynome bilden
    while y>0:
        if y&1 == 1:
            p = p ^ x
        x = x << 1
        y = y >> 1
    f = 0b100011011   # jetzt modulo f(x)=x^8+x^4+x^3+x+1 rechnen
    while len(bin(p)) >= 11:
        p = p ^ (f<<(len(bin(p))-11))
    return p

def main():
    print (F256Add(123, 45))
    print (F256Mul(123, 45))

if __name__ == "__main__":
    main()
