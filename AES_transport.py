import ssl
ctx = ssl.create_default_context()
ctx.set_ciphers('AES128-CCM')
list = ctx.get_ciphers()
print(list)
# for cipher in list:
#     if cipher['name'] == ''
# Seems like python ssl library don't have no TLS PSK mode

# I Don't know the difference between OpenSSL and SSL libaries in python.