certs: 
	@openssl genrsa -out server_privkey.pem 2048
	@openssl rsa -in server_privkey.pem -pubout -out server_pubkey.pem
