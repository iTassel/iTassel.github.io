
str1 = "something is wrong"
str2 = "uikcrnoha&ou&qtiha"
hint = []
for i in range(len(str1)):
	hint.append(ord(str1[i]) ^ ord(str2[i]))
print hint
