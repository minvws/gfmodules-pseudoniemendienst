Generate the following keys (demo only):

    openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048 && openssl rsa -in private.key -pubout -out public.pem
    poetry run python3 -c "import pyoprf; print(pyoprf.keygen().hex())" > prs.key

