import os

for trial in range(1,41):
	print(trial)
	for rnd in range(0,35):
		os.system('./TestHEAAN Encrypt '+ str(rnd)+' '+str(trial))


