PRIVKEY := keys/root_priv.pem
PUBKEY := keys/root_pub.pem
ROOT_PUBKEY := root_pubkey.pem
all:
	@echo run \"make keys\" if you are sure to generate/overwrite the root key
	exit 1
keys:
	mkdir -p keys
	@echo "Generating a guest signing key pair"
	openssl ecparam -name prime256v1 -genkey -noout -out $(PRIVKEY)
	openssl pkey -in  $(PRIVKEY) -pubout -out $(PUBKEY)


clean:
	rm -f $(PRIVKEY) $(PUBKEY)

.PHONY: all clean keys
