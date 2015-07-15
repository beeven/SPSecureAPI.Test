from cffi import FFI

ffi = FFI()

with open("./AppData/SPSecureAPI.h") as f:
	header = f.read()

ffi.cdef(header)

lib = ffi.dlopen("./AppData/SPSecureAPI.dll")


def invoke(func, *args):
	retcode = func(*args)
	if retcode != 0:
		ret = lib.SpcGetErrMsg(retcode)
		print ret
		raise

invoke(lib.SpcInitEnvEx)

invoke(lib.SpcVerifyPIN,ffi.new("char[]","88888888"),8)

userName = ffi.new("char[250]")
lenUserName = ffi.new("unsigned int*")
lenUserName[0] = 250

invoke(lib.SpcGetCardUserInfo,userName, lenUserName)
print "Actual len:",len(userName)," ret len: ",lenUserName[0]
print ffi.string(userName)

cert = ffi.new("uint8_t[4096]")
lenCert = ffi.new("unsigned int*")
lenCert[0] = 4096
invoke(lib.SpcGetEnvCert,cert, lenCert)
print "Cert Len:",lenCert[0]
print bytes(ffi.buffer(cert,lenCert[0]))


lib.SpcClearEnv()

