PRS_NAME=prs:app
PRS_HOST=0.0.0.0
PRS_PORT=8000

RECEIVER_NAME=receiver:app
RECEIVER_HOST=0.0.0.0
RECEIVER_PORT=8001

PRIVATE_KEY=private.pem
PUBLIC_KEY=public.pem

.PHONY: run gen-certs

gen-certs:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(PRIVATE_KEY)
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY)
	@echo "Keys generated: $(PRIVATE_KEY), $(PUBLIC_KEY)"

run:
	poetry run uvicorn $(PRS_NAME) --host $(PRS_HOST) --port $(PRS_PORT) --reload &
	poetry run uvicorn $(RECEIVER_NAME) --host $(RECEIVER_HOST) --port $(RECEIVER_PORT) --reload &
	wait

run-client:
	poetry run python client.py
