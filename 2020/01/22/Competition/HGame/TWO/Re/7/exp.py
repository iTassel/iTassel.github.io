str = ("7d037d045717722d62114e6a5b044f2c184c3f44214c2d4a22").decode("hex")
'''
for i in range(1,len(list)):
	n = (list[i-1]^list[i])
	list[i] = n
'''
flag = ''
for i in range(len(str)-1,0,-1):
	flag += chr(ord(str[i])^ord(str[i-1])%255)
print flag+'}'
##hgame{sT4cK_1$_sO_e@Sy~~}
