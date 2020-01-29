import ascii
TABLE = 'zxcvbnmasdfghjklqwertyuiop1234567890QWERTYUIOPASDFGHJKLZXCVBNM'

MOD = len(TABLE) #62

string = 'A8I5z{xr1A_J7ha_vG_TpH410}'
str = 'A8I5z'
str2 = 'hgame'
#for p in range(0,5):
for i in range(0,128):
	for n in range(0,128):
		if  (TABLE.find(str2[0])*i+n)%MOD == TABLE.find(str[0]) and  (TABLE.find(str2[1])*i+n)%MOD == TABLE.find(str[1]) and  (TABLE.find(str2[2])*i+n)%MOD == TABLE.find(str[2]) and  (TABLE.find(str2[3])*i+n)%MOD == TABLE.find(str[3]) and  (TABLE.find(str2[4])*i+n)%MOD == TABLE.find(str[4]):
			print hex(i)+ '   ' + hex(n)

flag = ''
list = []
var = []
def judge(var):
	if var == -1:
		return -1
	for i in range(0,32):
		if ((var+62*i-14)%13) == 0:
			return ((var+62*i-14)/13)

for n in string:
	list.append(TABLE.find(n))
for m in list:
	var.append(judge(m))
for i in  var:
	if i == -1:
		flag +='_'
	else:
		flag += TABLE[i]
print flag



