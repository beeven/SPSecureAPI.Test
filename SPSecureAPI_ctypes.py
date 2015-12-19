from ctypes import *
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import colorama
import OpenSSL


colorama.init()

lib = windll.LoadLibrary("./AppData/SPSecureAPI.dll")
#lib.SpcGetUName.argtypes = [c_char_p, POINTER(c_uint)]
#lib.SpcGetUName.restype = c_uint

def invoke(instruction,func,*args):
	print "{0:.<56}".format(instruction),
	retcode = func(*args)
	if retcode == 0:
		print "[" + colorama.Fore.GREEN +"OK"+ colorama.Fore.RESET + "]"
	else:
		print "[" + colorama.Fore.RED + "Failed"+ colorama.Fore.RESET + "]"
		ret = lib.SpcGetErrMsg(retcode)
		raise Exception(ret)

def generate_certificate_and_privkey():
	keypair = OpenSSL.crypto.PKey()
	keypair.generate_key(OpenSSL.crypto.TYPE_RSA,1024)
	cert = OpenSSL.crypto.X509()
	cert.get_subject().C = "CN"
	cert.get_subject().ST = "Guangdong"
	cert.get_subject().L = "Guangzhou"
	cert.get_subject().O = "GZC"
	cert.get_subject().OU = "IT"
	cert.get_subject().CN = "beeven@hotmail.com"
	cert.set_serial_number(1000)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(3*365*24*60*60)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(keypair)
	cert.sign(keypair,'sha1')
	c = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
	k = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,keypair)
	return (c,k)

# Generate testing certificate and key
cert_pem, privkey_pem = generate_certificate_and_privkey()


# Convert cert from pem to der
MyCert = create_string_buffer(2048)
lenMyCert = c_uint(2048)
# Need to trim "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
cert_pem_trim = "".join(cert_pem.split("\n")[1:-2])
invoke("Convert Certificate PEM to der",
	lib.SpcDecodePEM,
	cert_pem_trim,
	len(cert_pem_trim),
	MyCert,
	byref(lenMyCert)
)
cert_der = MyCert.raw[:lenMyCert.value]



# Convert key from pem to der using cryptography library
privkey = serialization.load_pem_private_key(
	privkey_pem,
	password = None,
	backend = default_backend()
)


# Initialization
invoke("Initialze Device", lib.SpcInitEnvEx)

# Verify pin
invoke("Verify PIN", lib.SpcVerifyPIN, "88888888",8)


# Get user name
lenUserName = c_uint(100)
userName = create_string_buffer(100)
invoke("Get user name", lib.SpcGetUName, userName, byref(lenUserName))
#print "\tUsername:{0} length:{1}".format(userName.value,lenUserName.value)


# Extract signing certificate
lenSigningCert = c_uint(2048)
signingCert = create_string_buffer(2048)
invoke("Extract signing certificate", lib.SpcGetSignCert, signingCert, byref(lenSigningCert))
signingCertificate = signingCert.raw[:lenSigningCert.value]
# with open("KeySign.cer","wb") as f:
# 	f.write(signingCertificate)


# Extract encryption certificate
lenEncCert = c_uint(2048)
encCert = create_string_buffer(2048)
invoke("Extract encryption certificate", lib.SpcGetEnvCert, encCert, byref(lenEncCert))
encCertificate = encCert.raw[:lenEncCert.value]
# with open("KeyEnc.cer","wb") as f:
# 	f.write(encCertificate)




### RSA Sigature ################################


message = b"This is the content."

# Signing with KEY
lenSignature = c_uint(256)
signature = create_string_buffer(256)
invoke(
	"Sign a message with KEY", 
	lib.SpcSignData, 
	message, 
	len(message), 
	signature, 
	byref(lenSignature)
)
# with open("message.sig","wb") as f:
# 	f.write(signature[:lenSignature.value])


# Verify the signature with cryptography
print "{0:.<56}".format("Verify signature with crytography library"),
cert = x509.load_der_x509_certificate(signingCertificate,default_backend())
pubkey = cert.public_key()
verifier = pubkey.verifier(
	signature.raw[:lenSignature.value],
	padding.PKCS1v15(), # Not PSS
	hashes.SHA1()
)
verifier.update(message)
try:
	verifier.verify()
	print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"
except cryptography.exceptions.InvalidSignature:
	print "[" + colorama.Fore.RED + "Failed" + colorama.Fore.RESET + "]"

# Verify the signature with public key
pubKey = create_string_buffer(150)
lenPubKey = c_uint(150)

invoke(
	"Get public key from certificate",
	lib.SpcGetCertPubKey,
	signingCertificate,
	len(signingCertificate),
	pubKey,
	byref(lenPubKey)
)



# Verify the signature with Cert using key
invoke(
	"Verify signature with KEY",
	lib.SpcVerifySignData,
	signingCertificate,
	len(signingCertificate),
	message,
	len(message),
	signature,
	lenSignature
)



############################################################


# Sign a message with cryptography library
print "{0:.<56}".format("Sign a message with cryptography library"),
signer = privkey.signer(
	padding.PKCS1v15(),
	hashes.SHA1()
)
signer.update(message)
signature = signer.finalize()
print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"


# Verify signature with cryptography library
print "{0:.<56}".format("Verify the signature with cryptography library"),
verifier = privkey.public_key().verifier(
	signature,
	padding.PKCS1v15(),
	hashes.SHA1()
)
verifier.update(message)
try:
	verifier.verify()
	print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"
except cryptography.exceptions.InvalidSignature:
	print "[" + colorama.Fore.RED + "Failed" + colorama.Fore.RESET + "]"


# Verify signature with public key
pubKey = create_string_buffer(150)
lenPubKey = c_uint(150)

invoke(
	"Get public key from certificate",
	lib.SpcGetCertPubKey,
	cert_der,
	len(cert_der),
	pubKey,
	byref(lenPubKey)
)

invoke(
	"Verify signature with public key",
	lib.SpcVerifySignWithPubKey,
	pubKey,
	128,
	message,
	len(message),
	signature,
	128
)

# Verify signature with KEY
invoke(
	"Verify signature of the message with KEY",
	lib.SpcVerifySignData,
	cert_der,
	len(cert_der),
	message,
	len(message),
	signature,
	128
)




### RSA Encryption ####################

# Encrypt data with cryptography using RSA-PKCS1v15
print "{0:.<56}".format("RSA encrypt message with cryptography library"),
message = b"encrypted data"
cert = x509.load_der_x509_certificate(encCert.raw[:lenEncCert.value],default_backend())
pubkey = cert.public_key()
ciphertext = pubkey.encrypt(
	message,
	padding.PKCS1v15() # Not OAEP
)
print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"


# Decryption data with KEY
messageOut = create_string_buffer(1024)
lenMessageOut = c_uint(1024)
invoke(
	"RSA decrypt message with KEY",
	lib.SpcRSADecrypt,
	ciphertext,
	len(ciphertext),
	messageOut,
	byref(lenMessageOut)
)
#print "\tContent:", messageOut.raw[:lenMessageOut.value]
print "{0:.<56}".format("RSA encrypt data with cryptography and decrypt with KEY"),
if message == messageOut.raw[:lenMessageOut.value]:
	print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"
else:
	print "[" + colorama.Fore.RED + "Failed" + colorama.Fore.RESET + "]"


# Encrypt data with KEY
ciphertextOut = create_string_buffer(1024)
lenCiphertextOut = c_uint(1024)
invoke(
	"RSA encrypt message with KEY",
	lib.SpcRSAEncrypt,
	cert_der,
	len(cert_der),
	message,
	len(message),
	ciphertextOut,
	byref(lenCiphertextOut)
)
ciphertext = ciphertextOut.raw[:lenCiphertextOut.value]

# Decrypt data with cryptography library
print "{0:.<56}".format("RSA decrypt message with cryptography library"),
plaintext = privkey.decrypt(
	ciphertext,
	padding.PKCS1v15()
)
print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"

print "{0:.<56}".format("RSA encrypt data with KEY and decrypt with cryptography"),
if plaintext == message:
	print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"
else:
	print "[" + colorama.Fore.RED + "Failed" + colorama.Fore.RESET + "]"



# Seal Envelope
ciphertextOut = create_string_buffer(1024)
lenCiphertextOut = c_uint(1024)
invoke(
	"Seal envelope",
	lib.SpcSealEnvelope,
	encCertificate,
	len(encCertificate),
	message,
	len(message),
	ciphertextOut,
	byref(lenCiphertextOut)
)

messageOut = create_string_buffer(1024)
lenMessageOut = c_uint(1024)
invoke(
	"Open envelope",
	lib.SpcOpenEnvelope,
	ciphertextOut,
	lenCiphertextOut,
	messageOut,
	byref(lenMessageOut)
)

print "{0:.<56}".format("Seal and open envelope"),
if message == messageOut.raw[:lenMessageOut.value]:
	print "[" + colorama.Fore.GREEN + "OK" + colorama.Fore.RESET + "]"
else:
	print "[" + colorama.Fore.RED + "Failed" + colorama.Fore.RESET + "]"




# Release
invoke("Release resources", lib.SpcClearEnv)

