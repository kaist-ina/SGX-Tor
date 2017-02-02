import sys, os

cert_list = []
fing_list = []
ip_list = ["10.0.0.1", "10.0.0.3", "10.0.0.4"]

for i in range(1,4):

	cert_finger = ""
	fing_finger = ""
	try:
		f = open("C:/Users/INA-SGX-USER/Desktop/TorVS2012/nodes/A00"+str(i)+"/keys/authority_certificate", 'r')
		while True:
			line = f.readline()
			if line.find("fingerprint") != -1:
				cert_finger = line.split(' ')[1][:-1]
				print "Found fingerprint in nodes/A00"+str(i)+"/certficate: " + cert_finger
				break
		f.close()

		f = open("C:/Users/INA-SGX-USER/Desktop/TorVS2012/nodes/A00"+str(i)+"/fingerprint", 'r')
		line = f.readline()
		fing_finger = line.split(' ')[1][:-1]
		print "Found fingerprint in nodes/A00"+str(i)+"/fingerprint: " + fing_finger
		f.close()

		if cert_finger == "":
			print "there are no fingerprint in nodes/A00"+str(i)+"/certificate 00"+str(i)
			os.system('pause')
			sys.exit()
		if fing_finger == "":
			print "there are no fingerprint in nodes/A00"+str(i)+"/fingerprint 00"+str(i)
			os.system('pause')
			sys.exit()

		cert_list.append(cert_finger)
		fing_list.append(fing_finger)
	except IOError as e:
		print str(e)
		os.system('pause')
		sys.exit()


print "\nOpen torrc and write fingerprints...\n"

def change_dirauth(torrc_alpha, torrc_num):
	newlines = []
	torrc_name = "C:/Users/INA-SGX-USER/Desktop/TorVS2012/nodes/"+torrc_alpha+"00"+str(torrc_num)+"/torrc"
	torrc_num += 1
	if torrc_num > 4:
		torrc_num = 1
	print "Reading ("+torrc_name+") ..."
	f = open(torrc_name, 'r')
	lines = f.readlines()
	cnt = 1
	for line in lines:
		if line.find("DirAuthority") != -1 and cnt < 4:
			line = "DirAuthority inaTorAuth"+str(cnt)+" orport=500"+str(cnt)+ \
			" no-v2 v3ident="+cert_list[cnt-1]+" "+ip_list[cnt-1]+":700"+str(cnt)+" "+fing_list[cnt-1]+"\n"
			cnt += 1
			print line[:-1]
		newlines.append(line)		
	f.close()

	if cnt != 4:
		print " *** ERROR! The number of DirAuthority is not 3! ***"
		print " *** I wrote "+str(cnt-1)+" lines\n"

	print "Writing ("+torrc_name+") ..."
	f = open(torrc_name, 'w')
	for line in newlines:
		f.write(line)
	print "Write done: "+torrc_name+"\n"
	f.close()

change_dirauth("A", 1)
change_dirauth("A", 2)
change_dirauth("A", 3)
change_dirauth("R", 1)
change_dirauth("R", 2)
change_dirauth("R", 3)
change_dirauth("C", 1)


print "Program done"
os.system('pause')