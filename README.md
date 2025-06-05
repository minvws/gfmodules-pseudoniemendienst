# PRS POC


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

```
$ openssl pkcs12 -export -out secrets/uzi-server-ca.p12 -inkey uzi-server-ca.key -in uzi-server-ca.crt
```
It will ask for a password, you can use anything.
Then import the uzi.p12 file into your browser. Again, the password is being asked.

At this point, you would be able to load the mTLS version on https://prs:6503. The connection should be secure as the
browser has the correct CA for the server certificate.

You probably get asked for a client certificate. Here you can use a client certificate that is signed by the uzi ca. 
For this you can use either `prs-client-1` or `prs-client-2` (same types). Note that you might need to import these 
into your browser through pkcs12 again:

```
$ openssl pkcs12 -export -out secrets/prs-client-1.p12 -inkey prs-client-1.key -in prs-client-1.crt
$ openssl pkcs12 -export -out secrets/prs-client-2.p12 -inkey prs-client-2.key -in prs-client-2.crt
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
