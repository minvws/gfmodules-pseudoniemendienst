# PRS


## Run the following commands to run the project:

```bash
docker compose up
```

This will start the project on 'http://localhost:6502'



# Using mTLS

To use/test mTLS, you need to setup the following:

first, the server is configured with server name "prs", meaning you need to add this to your /etc/hosts (or equivalent):

```
  127.0.0.1 prs
```

Next, since the prs certificate is signed with our own development uzi ca cert, you need to import (temporarily) the uzi
ca cert into your browser. Normally, this is done via pkcs12:

```bash
openssl pkcs12 -export -out secrets/uzi-server-ca.p12 -inkey uzi-server-ca.key -in uzi-server-ca.crt
```
It will ask for a password, you can use anything.
Then import the uzi.p12 file into your browser. Again, the password is being asked.

At this point, you would be able to load the mTLS version on https://prs:6503. The connection should be secure as the
browser has the correct CA for the server certificate.

You probably get asked for a client certificate. Here you can use a client certificate that is signed by the uzi ca. 
For this you can use either `prs-client-1` or `prs-client-2` (same types). Note that you might need to import these 
into your browser through pkcs12 again:

```bash
openssl pkcs12 -export -out secrets/prs-client-1.p12 -inkey prs-client-1.key -in prs-client-1.crt
openssl pkcs12 -export -out secrets/prs-client-2.p12 -inkey prs-client-2.key -in prs-client-2.crt
```

If you weren't asked for a client certificate, make sure the site is secured correctly (you should see a lock in the 
url bar). If not, client certs are not asked by the browser.

It's also possible that client certificates are disabled for this site. In firefox, go to:  tools | settings | privacy & security |
certificates | view certificates | authentication decicions and delete the entry for the site. This will make the browser
ask for a client certificate again.


## Testing with OV or EV certificates
The easiest way to test for OV or EV certificates is to use the `auth.override_cert` configuration setting in app.conf. However,
if you want to test with apache, you must make sure that the CA for that OV or EV cert is inside the `SSLCACertificateFile` 
setting of httpd-ssl.conf.

To do that, concatenate the CA of the EV/OV file (including any intermediate certs) into the file pointed by `SSLCACertificateFile`.

When you now specify a client certificate signed by the CA of the EV/OV cert, the browser should connect and you are only able to
view/interact with certain endpoints.


# Docker container builds

There are two ways to build a docker container from this application. The first is the default mode created with:

```bash
docker build \
  --build-arg="NEW_UID=1000" \
  --build-arg="NEW_GID=1000" \
  -f docker/Dockerfile \
  -t gfmodules-prs \
  .
```
This will build a docker container that will run its migrations to the database specified in app.conf.

The second mode is a "standalone" mode, where it will not run migrations, and where you must explicitly specify
an app.conf mount.

```bash
docker build \
  --build-arg="standalone=true" \
  -f docker/Dockerfile \
  -t gfmodules-prs \
  .
```
Both containers only differ in their init script and the default version usually will mount its own local src directory
into the container's /src dir.

```bash
docker run -ti --rm -p 6502:6502 \
  --mount type=bind,source=./app.conf.example,target=/src/app.conf \
  --mount type=bind,source=./auth_cert.json.example,target=/src/auth_cert.json \
  --mount type=bind,source=./secrets,target=/src/secrets \
  gfmodules-prs
```



# OPRF Testing

This system uses OPRF for pseudonym generation. To test this, there are some available endpoints:

- '/test/oprf/gen_rsa_key' - Generate a new RSA keypair for OPRF (small 1024 bit for testing)
- '/test/oprf/oprf/client' - Emulates a client that generates OPRF information for a given input
- '/test/oprf/oprf/receiver' - Emulates the receiver of the pseudonym and returns diagnostic information

To use this system:

1. First, generate a new keypair that will be used for a test organization with `/test/oprf/gen_rsa_key`.
   ```shell
    POST /test/oprf/gen_rsa_key 
   
    200 OK
    {
      "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMIICdwIBA....neDKJ0DsvA5vfpt0=\n-----END PRIVATE KEY-----\n",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqG....uDQIDAQAB\n-----END PUBLIC KEY-----\n",
      "public_key_kid": "ajGAx_LKNrJ8vqdahWlSJvOznBi6lnFfSOw72Z4R4uU"
    } 
   ```
 
2. Create a new organization into the key resolver with a POST to `/keys`. Add your organization name like 
   `ura:12345678`, and you can use scope `test` for testing. Add the **PUBLIC key** to the `public_key` field.

    ```shell
    POST /keys
    {
      "organization": "ura:12345678",
      "scope": "test",
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqG....uDQIDAQAB\n-----END PUBLIC KEY\n",
    }
   
    201 Created
    ```

3. Emulate a client wanting to send a pseudonym over to a receiver by calling `/test/oprf/client` with a JSON body like:

   ```shell
   POST /test/oprf/client
   {
     "personalId": "testinput-like-a-bsn-number-or-other-id"
   }
   
   200 OK
   {
     "blinded_input": "EJU9qVhKNmw_UhCXDN_aVM4GL1DCmpDs8QD5WOdUBCU=",
     "blind_factor": "eNf80WNHbImaUNU-kokBr7ocELBjMtHcy0re_RKBPQ8="
   }
   ```

   This returns the `blinded_input` that must be sent to the receiver, and the `blind_factor` that must be send to the
   receiver after the server has evaluated the blinded input.

4. Now we can call the "real" OPRF function `/oprf/eval` with the blinded input, the organization name and scope:
   
      ```shell
      POST /oprf/eval
      {
        "encryptedPersonalId": "EJU9qVhKNmw_UhCXDN_aVM4GL1DCmpDs8QD5WOdUBCU=",
        "recipientOrganization": "ura:12345678",
        "recipientScope": "test"
      }

      200 OK
      {
        "jwe": "eyJraWQiOi....bJUqbbSUIjqiw"
      } 
      ```
   
   At this point we will get back a JWE that contains the evaluated blinded input and
   is encrypted with the public key of the organization. At this point, the client is 
   not able to decrypt this information. It can only forward this to the receiver.

5. Now emulate the receiver by calling `/test/oprf/receiver` with a JSON body like:
   ```shell   
    POST /test/oprf/receiver
    {
      "blind_factor": "eNf80WNHbImaUNU-kokBr7ocELBjMtHcy0re_RKBPQ8=",
      "jwe": "eyJraWQiOiA...SzZbJUqbbSUIjqiw",
      "priv_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIB...oCfe0=\n-----END RSA PRIVATE KEY-----\n"
    }
   ```
   
    The blind factor is the one returned by the client, the JWE is the one returned by the prs evaluation, and 
    the private key is returned by the key generation step.

    At this point, it will return any diagnostic information about the OPRF process:

    ```json
    {
      "jwe_data": "eyJraWQiOiAi...zZbJUqbbSUIjqiw",
      "priv_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgH6gmpXpdhtiE...UpWRvoCfe0=\n-----END RSA PRIVATE KEY-----\n",
      "priv_key_kid": "rNv1O_mXgxF6QEMfaQGvjev7RbT1FG3sJXxxsu_KHbM",
      "blind_factor": "eNf80WNHbImaUNU-kokBr7ocELBjMtHcy0re_RKBPQ8=",
      "jwe": {
        "headers": {
          "kid": "rNv1O_mXgxF6QEMfaQGvjev7RbT1FG3sJXxxsu_KHbM",
          "alg": "RSA-OAEP-256",
          "enc": "A256GCM",
          "cty": "application/json"
        },
        "decrypted": {
          "subject": "pseudonym:eval:-Jpsoeik2058ip20b9Wd-vlwpjkjxRN4IoBrk8Ym2Bg=",
          "aud": "ura:12345678",
          "scope": "nvi",
          "version": "1.1",
          "iat": 1758616285,
          "exp": 1758616585
        }
      },
      "eval_subject": "-Jpsoeik2058ip20b9Wd-vlwpjkjxRN4IoBrk8Ym2Bg=",
      "final_pseudonym": "fDZYIlajLAV3y8fWl1ObFBDmybUEGrR37pDb-5p5pJJGKvvpDvvMdQmYHKqtiQ8tdF4VL3w8nkbssHtOmkjiOg=="
    }
    ```

    The `final_pseudonym` is the actual pseudonym that can be stored by the receiver. Note that this pseudonym is deterministic
    for the same input, organization and scope. However, it is not possible to reverse this into a BSN.
