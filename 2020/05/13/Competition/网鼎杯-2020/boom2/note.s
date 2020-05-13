虚拟栈初始化完之后,RSP+0X18 = SP; RSP+0X20 = BP; RSP+0X28 = RA;
00:	RA = BP + OPCODE*8
01:	RA = OPCODE
06:	PUSH BP
	MOV BP,SP
	SUB SP,OPCODE*8
08:	MOV SP,BP
	POP BP
09:	RA = [RA]
10:	AL = [RA]
11:	[[SP]] = RA
	ADD SP,8
12:	[[SP]] = RA
	RA = [SP]
	ADD SP,8
13:	PUSH RA
14:	RA = [SP] | RA
	ADD SP,8
15:	RA = [SP] ^ RA
	ADD SP,8
16:	RA = [SP] & RA	
	ADD SP,8
17:	if [SP] == RA
		RA = 1
	else
		RA = 0
	ADD SP,8
18:	if [SP] != RA
		RA = 1
	else
		RA = 0
	ADD SP,8
19:	if [SP] < RA
		RA = 1
	else
		RA = 0
	ADD SP,8
20:	if [SP] > RA
		RA = 1
	else
		RA = 0
	ADD SP,8
21:	if [SP] <= RA
		RA = 1
	else
		RA = 0
	ADD SP,8
22:	if [SP] >= RA
		RA = 1
	else
		RA = 0
	ADD SP,8
23:	RA = [SP] << RA
	ADD SP,8
24:	RA = [SP] >> RA
	ADD SP,8
25:	RA = [SP] + RA
	ADD SP,8
26: RA = [SP] - RA
	ADD SP,8
27:	RA = [SP] * RA
	ADD SP,8
28:	RA = [SP] / RA
	ADD SP,8
28:	RA = [SP] % RA
	ADD SP,8
