#coding=utf-8

import sys,os,time
import urllib,hashlib
import base64,binascii


def url_encode(s):
  try:
    r=urllib.quote(s)
    if r:
      print('url encode: ',r)
  except:
    pass

def url_decode(s):
  try:
    r=urllib.unquote(s)
    if r:
      print('url decode: ',r)
  except:
    pass
	
def gbk_encode(s):
  try:
    r=s.encode('gbk', 'replace')
    if r:
      print('gbk encode: ',r)
  except:
    pass


def gbk_decode(s):
  try:
    r=s.decode('gbk', 'replace')
    if r:
      print('gbk decode: ',r)
  except:
    pass

def utf8_encode(s):
  try:
    r=s.encode('utf-8', 'replace')
    if r:
      print('utf8 encode: ',r)
  except:
    pass


def utf8_decode(s):
  try:
    r=s.decode('utf-8', 'replace')
    if r:
      print('utf8 decode: ',r)
  except:
    pass

def ascii_encode(s):
  try:
    r=s.encode('ascii', 'replace')
    if r:
      print('ascii encode: ',r)
  except:
    pass


def ascii_decode(s):
  try:
    r=s.decode('ascii', 'replace')
    if r:
      print('ascii decode: ',r)
  except:
    pass

def iso88591_encode(s):
  try:
    r=s.encode('ISO-8859-1', 'replace')
    if r:
      print('iso-8859-1 encode: ',r)
  except:
    pass


def iso88591_decode(s):
  try:
    r=s.decode('ISO-8859-1', 'replace')
    if r:
      print('iso-8859-1 decode: ',r)
  except:
    pass

def utf16_encode(s):
  try:
    r=s.encode('utf-16', 'replace')
    if r:
      print('utf-16 encode: ',r)
  except:
    pass


def utf16_decode(s):
  try:
    r=s.decode('utf-16', 'replace')
    if r:
      print('utf-16 decode: ',r)
  except:
    pass

def hex_encode(s):
  try:
    r=''.join([binascii.b2a_hex(i) for i in s])
    if r:
      print('hex encode: ',r)
  except:
    pass
	
def byte_encode(s):
  try:
    rr=''.join([binascii.b2a_hex(i) for i in s])
    r='\\x'+'\\x'.join([rr[i:i+2] for i in xrange(len(rr)) if i%2==0])
    if r:
      print('byte encode: ',r)
  except:
    pass
	
def sql_encode(s):
  try:
    r='0x'+'00'.join([binascii.b2a_hex(i) for i in s])+'00'
    if r:
      print('sql query encode: ',r)
  except:
    pass

def url_total_encode(s):
  try:
    rr=[binascii.b2a_hex(i) for i in s]
    r='%'+'%'.join([i for i in rr])
    if r:
      print('url total encode: ',r)
  except:
    pass
	
def url_total_decode(s):
  try:
    rr=[s[i+1:i+3] for i in xrange(len(s)) if i%3==0]
    r=''.join([binascii.a2b_hex(i) for i in rr])
    if r:
      print('url total decode: ',r)
  except:
    pass

def hex_decode(s):
  try:
    rr=[s[i:i+2] for i in xrange(len(s)) if i%2==0]
    r=''.join([binascii.a2b_hex(i) for i in rr])
    if r:
      print('hex decode: ',r)
  except:
    pass

def byte_decode(s):
  try:
    rr=[s[i+2:i+4] for i in xrange(len(s)) if i%4==0]
    r=''.join([binascii.a2b_hex(i) for i in rr])
    if r:
      print('byte decode: ',r)
  except:
    pass
	
def md5_encode(s):
  rr=hashlib.md5()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('md5 encrypt: ',r)
  
def md4_encode(s):
  r=hashlib.new('md4', s.encode('utf-16le')).hexdigest().upper()
  print('md4 encrypt: ',r)
  
def md5_16_encode(s):
  rr=hashlib.md5()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()[8:24]
  print('md5-16 encrypt: ',r)
  
def sha1_encode(s):
  rr=hashlib.sha1()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('sha1 encrypt: ',r)
  
def sha256_encode(s):
  rr=hashlib.sha256()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('sha256 encrypt: ',r)
  
def sha224_encode(s):
  rr=hashlib.sha224()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('sha224 encrypt: ',r)
  
def sha384_encode(s):
  rr=hashlib.sha384()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('sha384 encrypt: ',r)
  
def sha512_encode(s):
  rr=hashlib.sha512()
  rr.update(s.encode('utf-8', 'replace'))
  r=rr.hexdigest()
  print('sha512 encrypt: ',r)
  
def b64_encode(s):
  r=base64.b64encode(s)
  print('base64 encode: ',r)

def b64_decode(s):
  try:
    r=base64.b64decode(s)
    if r:
      print('base64 decode: ',r)
  except:
    pass

def b32_encode(s):
  r=base64.b32encode(s)
  print('base32 encode: ',r)

def b32_decode(s):
  try:
    r=base64.b32decode(s)
    if r:
      print('base32 decode: ',r)
  except:
    pass
	
def b16_encode(s):
  r=base64.b16encode(s)
  print('base16 encode: ',r)

def b16_decode(s):
  try:
    r=base64.b16decode(s)
    if r:
      print('base16 decode: ',r)
  except:
    pass
	
def asc_decode(s):
  try:
    r=''.join([str(ord(i)) for i in s])
    if r:
      print('asc decode: ',r)
  except:
    pass
	
if __name__=='__main__':
  try:
    s=sys.argv[1]
  except:
    print('usage: %s keyword' % sys.argv[0])
    exit()
  try:
    print('your input is ',s)
    url_encode(s)
    url_decode(s)
    gbk_encode(s)
    gbk_decode(s)
    utf8_encode(s)
    utf8_decode(s)
    ascii_encode(s)
    ascii_decode(s)
    iso88591_encode(s)
    iso88591_decode(s)
    utf16_encode(s)
    utf16_decode(s)
    hex_encode(s)
    byte_encode(s)
    sql_encode(s)
    asc_decode(s)
    url_total_encode(s)
    url_total_decode(s)
    hex_decode(s)
    byte_decode(s)
    md4_encode(s)
    md5_encode(s)
    md5_16_encode(s)
    sha1_encode(s)
    sha224_encode(s)
    sha256_encode(s)
    sha384_encode(s)
    sha512_encode(s)
    b64_encode(s)
    b64_decode(s)
    b32_encode(s)
    b32_decode(s)
    b16_encode(s)
    b16_decode(s)
  except Exception,e:
    print(e)
    pass
