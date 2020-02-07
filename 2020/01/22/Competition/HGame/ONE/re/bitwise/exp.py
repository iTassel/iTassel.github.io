import string
str_I  = 'e4sy_Re_'
str_II = 'Easylif3'
List = [76,60,-42,54,80,-120,32,-52]
flag_I  = []
flag_II = []
for i in range(0,8):
	P = (List[i]^ord(str_I[i]))%256
	flag_I.append(P)
for l in range(0,8):
	Q = ( (ord(str_I[l])^List[l]) ^ord(str_II[l])) %256
	flag_II.append(Q)
print flag_I
print flag_II

flag_III = []
flag_IV = []	
# from back to front
for c in range(7,-1,-1): 
	count = 0
	for n in range(0,256):
		if flag_I[c] == (((n&0x55) ^ ((flag_II[7-c]&0xAA)>>1))| (n&0xAA))%256:
			T1 = n	
			count +=1
			break;
	for n in range(0,256):
		if flag_II[7-c] == ((2*( T1&0x55 )^ (n&0xAA)) | (n&0x55))%256:
			T2 = n
			count +=1
			break;
	for n in range(0,256):
		if T1== ((n&0x55) ^ ( (T2 &0xAA)>>1) | (n&0xAA))%256:
			T1 = n
			count +=1
			break;
	for n in range(0,256):	
		if T1 ==(((n&0xE0)>>5)| (8*n))%256:
			T1 = n
			count +=1
			break;
	flag_III.append(T1)
	flag_IV.append(T2)
	print count
flag_III.reverse()
print flag_III
print flag_IV

def re(list):
	I = []
	II = []
	for c in range(0,8):
		for i in range(0,0x10):
			for n in range(0,0x10):
				if list[c] ==  0x10* i + n:
					I.append(i)
					II.append(n)
	flag = ''
	print I
	print II
	for q in range(0,8):
		if I[q] >=0 and I[q] <= 9:
			I[q] += 48
		else:
			I[q] +=87
		if II[q] >=0 and II[q] <= 9:
			II[q] += 48
		else:
			II[q] +=87
		#print 'ONE:\t'+chr(I[q]) + ' TWO\t' + chr(II[q])
		flag +=( chr(I[q])+chr(II[q]))
	return flag
str = re(flag_III)+re(flag_IV)
print str

