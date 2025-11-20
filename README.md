# GFModules Pseudoniemendienst

This app is the 'Pseudoniemendienst' and is part of the 'Generieke Functies, lokalisatie en addressering' project of the 
Ministry of Health, Welfare and Sport of the Dutch government. 

The Pseudoniemendienst is a **Proof of Concept** application that explores the functionality and requirements of a 
pseudonymization service for pseudonymizing the **Dutch citizen number (BSN)** in various healthcare applications.

The Pseudoniemendienst is used in the [Nationale Verwijsindex](#nationale-verwijsindex--), by the
**Vertrouwde Authenticatie Dienst (VAD)** and in the
[MedMij afsprakenstelsel](https://medmij.nl/medmij-afsprakenstelsel/).

## Disclaimer

This project and all associated code serve solely as documentation
and demonstration purposes to illustrate potential system
communication patterns and architectures.

This codebase:

- Is NOT intended for production use
- Does NOT represent a final specification
- Should NOT be considered feature-complete or secure
- May contain errors, omissions, or oversimplified implementations
- Has NOT been tested or hardened for real-world scenarios

The code examples are only meant to help understand concepts and demonstrate possibilities.

By using or referencing this code, you acknowledge that you do so at your own
risk and that the authors assume no liability for any consequences of its use.

## Development setup

This project can be setup and tested either as a python application directly on an operating system or in a Docker 
environment. 

> **Quickstart**
> 
> The easiest way is to start the docker-compose project by running:
> 
> ```bash
> docker compose up
> ```
> This will start the project on 'http://localhost:6502'
>

### Docker development setup

The docker compose file contains the required databases, an SSL offloading apache container and the python app itself.

You can start the services without the SSL offloading service by running:

```bash
docker compose up
```

This will start the project on 'http://localhost:6502'

#### Using mTLS

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

You can start the services now by running:

```bash
docker compose --profile ssl up
```

## Poetry development setup

Sometimes it's required, or easier to run the application natively on an operating system. To run and test the
application on an operating system Poetry is used. Before you're able to install this project, the following
requirements needs to be available:

* [Poetry](#poetry)
* [pkgconf](#pkgconf)
* [libsodium-dev](#libsodium-dev)
* [liboprf](#liboprf)

### Poetry Development dependencies

#### Poetry

Please see the [official docs](https://python-poetry.org/docs/#installation) to follow the Poetry installation process.

#### pkgconf

This is required to build [liboprf](#liboprf).

You can check if [pkgconf](https://github.com/pkgconf/pkgconf) is installed by running:

```bash
which pkgconf
```

Installation instructions vary depending on the operating system and available package managers.

#### Libsodium-dev

This is required by [liboprf](#liboprf).

You can check if libsodium is installed by running:

```bash
pkgconf --modversion libsodium
```

See the [official installation instructions](https://doc.libsodium.org/doc/installation) to install libsodium.

#### liboprf

Liboprf is used by the OPRF functionality of the Pseudoniemendienst.

See the [installation instructions](https://github.com/stef/liboprf?tab=readme-ov-file#installation)
how to install this library.

After installing update the shared library cache by running:

```bash
sudo ldconfig
```

### Poetry pytest

The tests have a dependency on a postgres database. You can easily setup a database with docker:
```bash
docker compose up -d postgres
```

Now you're able to run the pytest in poetry:
```bash
poetry run pytest
```


## Testing with OV or EV certificates
The easiest way to test for OV or EV certificates is to use the `auth.override_cert` configuration setting in app.conf. However,
if you want to test with apache, you must make sure that the CA for that OV or EV cert is inside the `SSLCACertificateFile` 
setting of httpd-ssl.conf.

To do that, concatenate the CA of the EV/OV file (including any intermediate certs) into the file pointed by `SSLCACertificateFile`.

When you now specify a client certificate signed by the CA of the EV/OV cert, the browser should connect and you are only able to
view/interact with certain endpoints.


## Docker container builds

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

## OPRF Testing

This system uses OPRF for pseudonym generation. To test this, there are some available endpoints:

- '/test/oprf/oprf/client' - Emulates a client that generates OPRF information for a given input
- '/test/oprf/oprf/receiver' - Emulates the receiver of the pseudonym and returns diagnostic information

To use this system:

1. You will need a generated UZI Server certificate (https://www.uziregister.nl/servercertificaat) or create a 
   self-signed certificate for testing purposes.

   Since the system uses mTLS, you can either setup a mTLS setup (caddy, apache, etc), or enable the override in the
    app.conf file:
  
    ```
    [app]
    mtls_override_cert=./secrets/self-signed-uzi-server-cert.crt
 
2. Insert a new organization via a POST to `/orgs`. The organization ura should be the URA of the uzi certificate you 
   will be testing with.

   Note: there is no mTLS check here. You can add multiple organizations with different URA values for testing. 

3. Next, you will need to register your public key to the key services. You can do this by calling `/register/certificate` with a JSON body like:
   
   ```shell
   POST /register/certificate
   {
     "scope": [
        "nvi",
     ]
   }
   ```
   
   This will take the public key from the uzi server certificate using in this mTLS connection, and register it for the given scope.


4. Emulate a client wanting to send a pseudonym over to a receiver by calling `/test/oprf/client` with a JSON body like:

   ```shell
   POST /test/oprf/client
   {
     "personalId": "nl:bsn:950000012"
   }
   
   200 OK
   {
     "blinded_input": "EJU9qVhKNmw_UhCXDN_aVM4GL1DCmpDs8QD5WOdUBCU=",
     "blind_factor": "eNf80WNHbImaUNU-kokBr7ocELBjMtHcy0re_RKBPQ8="
   }
   ```

   This returns the `blinded_input` that must be sent to the receiver, and the `blind_factor` that must be sent to the
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

5. Now emulate the receiving party by calling `/test/oprf/receiver` with a JSON body like:
   ```shell   
    POST /test/oprf/receiver
    {
      "blind_factor": "eNf80WNHbImaUNU-kokBr7ocELBjMtHcy0re_RKBPQ8=",
      "jwe": "eyJraWQiOiA...SzZbJUqbbSUIjqiw",
      "priv_key_pem": "-----BEGIN RSA PRIVATE KEY----- MIICXAIB...oCfe0= -----END RSA PRIVATE KEY-----"
    }
   ```
   
    The blind factor is the one returned by the client, the JWE is the one returned by the prs evaluation, and 
    the private key is returned by the key generation step.

    At this point, it will return any diagnostic information about the OPRF process:

    ```json
    {
      "jwe_data": "eyJraWQiOiAi...zZbJUqbbSUIjqiw",
      "priv_key_pem": "-----BEGIN RSA PRIVATE KEY----- MIICXAIBAAKBgH6gmpXpdhtiE...UpWRvoCfe0= -----END RSA PRIVATE KEY-----",
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

## max-key-usage

The max-key-usage is a property that defines what kind of pseudonyms an organization can create and reverse.

There are 3 levels of max_key_usage:

- BSN - can create reversible and irreversible pseudonyms, and can reverse reversible pseudonyms back to BSN
- RP (Reversible Pseudonym) - can create reversible and irreversible pseudonyms, but cannot reverse any pseudonyms
- IRP (Irreversible Pseudonym) - can only create irreversible pseudonyms, and cannot reverse any pseudonyms

The "RP" level is mainly intended for organizations that need to create reversible pseudonyms for other organizations, 
but is not allowed to reverse them back to BSN itself.

The "IRP" level is intended for organizations that only need to create irreversible pseudonyms, and do not have access to 
BSN information at all.

## Contribution

As stated in the [Disclaimer](#disclaimer) this project and all associated code serve solely as documentation and
demonstration purposes to illustrate potential system communication patterns and architectures.

For that reason we will only accept contributions that fit this goal. We do appreciate any effort from the
community, but because our time is limited it is possible that your PR or issue is closed without a full justification.

If you plan to make non-trivial changes, we recommend to open an issue beforehand where we can discuss your planned changes. This increases the chance that we might be able to use your contribution (or it avoids doing work if there are reasons why we wouldn't be able to use it).

Note that all commits should be signed using a gpg key.
