import sys, os

cert_list = []
fing_list = []

for i in range(1,4):

	cert_finger = ""
	fing_finger = ""

	f = open("../nodes/00"+str(i)+"/keys/authority_certificate", 'r')
	while True:
		line = f.readline()
		if line.find("fingerprint") != -1:
			cert_finger = line.split(' ')[1][:-1]
			print "Found fingerprint in nodes/00"+str(i)+"/certficate: " + cert_finger
			break
	f.close()

	f = open("../nodes/00"+str(i)+"/fingerprint", 'r')
	line = f.readline()
	fing_finger = line.split(' ')[1][:-1]
	print "Found fingerprint in nodes/00"+str(i)+"/fingerprint: " + fing_finger
	f.close()

	if cert_finger == "":
		print "there are no fingerprint in nodes/00"+str(i)+"/certificate 00"+str(i)
		sys.exit()
	if fing_finger == "":
		print "there are no fingerprint in nodes/00"+str(i)+"/fingerprint 00"+str(i)
		sys.exit()

	cert_list.append(cert_finger)
	fing_list.append(fing_finger)

print "\nOpen torrc and write fingerprints...\n"

for i in range(1,7):
	newlines = []
	torrc_name = "../nodes/00"+str(i)+"/torrc"
	print "Reading ("+torrc_name+") ..."
	f = open(torrc_name, 'r')
	lines = f.readlines()
	cnt = 0
	for line in lines:
		if line.find("DirAuthority") != -1 and cnt < 3:
			line = "DirAuthority inaTor"+str(cnt+1)+" orport=500"+str(cnt)+ \
			" no-v2 v3ident="+cert_list[cnt]+" 127.0.0.1:700"+str(cnt)+" "+fing_list[cnt]+"\n"
			cnt += 1
			print line[:-1]
		newlines.append(line)		
	f.close()
	print "Writing ("+torrc_name+") ..."
	f = open(torrc_name, 'w')
	for line in newlines:
		f.write(line)
	print "Write done: "+torrc_name+"\n"
	f.close()

print "Program done"
os.system('pause')
