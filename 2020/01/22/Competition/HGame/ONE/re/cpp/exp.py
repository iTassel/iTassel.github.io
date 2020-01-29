from z3 import *
flag = [BitVec('u%d'%i,16) for i in range(0,9)]
solver = Solver()

solver.add((flag[0]+flag[2]) == 0x6867)
solver.add((flag[1]+2*flag[2]) == 0x616D)  
solver.add((flag[0] + flag[1]+2*flag[2]) == 0x65)

solver.add((flag[3]+flag[5]) == 0x7265)
solver.add((flag[4]+2*flag[5]) == 0x6973) 
solver.add((flag[3] + flag[4]+2*flag[5]) == 0x736F)

solver.add((flag[6]+flag[8]) == 0x736F)
solver.add((flag[7]+2*flag[8]) == 0x6561) 
solver.add((flag[6] + flag[7]+2*flag[8]) == 0x7379)

solver.check()
result = solver.model()

Str= ''
Bin = ''
for i in range(0,9):
    Str+= str(((result[flag[i]].as_long().real))).replace('0x','')+'_'

for i in range(0,3):
	Bin +=str(((result[flag[i]].as_long().real)))+'_'
print Str
print len(Bin)

##	hgame{-24840_-78193_51567_2556_-26463_26729_3608_-25933_25943}
