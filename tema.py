import os
from multiprocessing import Process, Pipe, Queue
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
iv="1001101001100010"
iv=str.encode(iv)
kprim=get_random_bytes(16)

def xor(b1,b2):
   return bytes([_a^_b for _a,_b in zip(b1,b2)])

def encryptCBC(k, q):
   f=open("filein.txt","r")
   cipher=AES.new(k,AES.MODE_EAX, iv)
   block=f.read(16)
   x=[]
   block=xor(str.encode(block),iv)
   cript=cipher.encrypt(block)
   q.put(cript)
   x.append(cript)
   while block!="":
      block=f.read(16)
      if block!="":
         cipher=AES.new(k,AES.MODE_EAX,iv)
         block=xor(str.encode(block),cript)
         cript=cipher.encrypt(block)
         q.put(cript)
         x.append(cript)
   q.put("OK")
   print(x)

def encryptOFB(k, q):
   f=open("filein.txt","r")
   cipher=AES.new(k,AES.MODE_EAX, iv)
   block=f.read(16)
   cript=cipher.encrypt(iv)
   block=xor(str.encode(block),cript)
   x=[]
   q.put(block)
   x.append(block)
   while block!="":
      block=f.read(16)
      if block!="":
         cipher=AES.new(k,AES.MODE_EAX,iv)
         cript=cipher.encrypt(cript)
         block=xor(str.encode(block),cript)
         q.put(block)
         x.append(block)
   q.put("OK")
   print(x)

def nodKM(q3):
   k=get_random_bytes(16)
   cipher=AES.new(kprim,AES.MODE_EAX, iv)
   k=cipher.encrypt(k)
   q3.put(k)

def nodA(q,msj,q3,q4,q5):
   q.put(msj)
   k=q3.get()
   q4.put(k)
   cipher=AES.new(kprim,AES.MODE_EAX, iv)
   k=cipher.decrypt(k)
   ok=q5.get()
   if msj=="CBC":
      print("cbc")
      encryptCBC(k,q)
   elif msj=="OFB":
      print("ofb")
      encryptOFB(k,q)
   else:
      print("Wrong mode")
def nodB(q,q4,q5):
   msj=q.get()
   k=q4.get()
   cipher=AES.new(kprim,AES.MODE_EAX, iv)
   k=cipher.decrypt(k)
   if msj=="CBC":
      q5.put("ok")
      cipher=AES.new(k,AES.MODE_EAX,iv)
      block=q.get()
      msj=""
      decript=cipher.decrypt(xor(block,iv))
      msj+=decript.decode("utf-8")
      decript=block
      while block!="OK":
         block=q.get()
         if block!="OK":
            cipher=AES.new(k,AES.MODE_EAX,iv)
            decript=cipher.decrypt(xor(block,decript))
            msj+=decript.decode("utf-8")
            decript=block
   elif msj=="OFB":
      q5.put("ok")
      cipher=AES.new(k,AES.MODE_EAX,iv)
      block=q.get()
      msj=""
      decript=cipher.encrypt(iv)
      block=xor(block,decript)
      msj+=block.decode("utf-8")
      while block!="OK":
         block=q.get()
         if block!="OK":
            cipher=AES.new(k,AES.MODE_EAX,iv)
            decript=cipher.encrypt(decript)
            block=xor(block,decript)
            msj+=block.decode("utf-8")
   print(msj)

if __name__=='__main__':
   msj=input("CBC SAU OFB: ")
   q=Queue()
   q3=Queue()
   q4=Queue()
   q5=Queue()
   p=Process(target=nodA, args=(q,msj,q3,q4,q5, ))
   p.start()
   b=Process(target=nodB, args=(q,q4,q5,))
   b.start()
   km=Process(target=nodKM, args=(q3,))
   km.start()
