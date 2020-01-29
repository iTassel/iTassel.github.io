import base64,string
str = '0g371wvVy9qPztz7xQ+PxNuKxQv74B/5n/zwuPfX'
S = 'abcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ASCII ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
list = []
flag = ''
for i in range(0,len(str)):
	n = S.find(str[i])
	list.append(n)
	flag += ASCII[n]
print list
print base64.b64decode(flag)
