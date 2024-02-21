# Mira REST API - Python Requests examples

## API Usage

The python requests library is commonly used to interact with web resources.
It is not specifically aimed at interacting with Swagger based REST API services
but can be used.

To interact with the ETO REST API, either a API Authentication Token or a session
cookie is required.

Please refer to the web ui developer documentation for details about available resources,
methods and parameters.

## [requests_access_example.py](requests_access_example.py)
This first example uses a username/password login via HTTPS to the /api/auth/login
to obtain a session token that can be used for subsequent communication with the
other API URLs.

This example program connects into the decryption appliance and lists all of the
available user accounts on the system along with their corresponding email address.
An example of the program output is shown below.

> \$ python requests_access_example.py -s https://*decrypt-1*/api/ -u *apiuser* -p *C0mpl3xpw#*
apiuser: Jack Restitt <developer@org.com>
admin:   <admin@example.com>

Note: an optional --noverify argument can be used to allow access to untrusted
self signed WebUI certificates, however this is not recommended for accessing
production systems, instead the WebUI appliance cert should be signed by a trusted
internal CA and verification always performed.

## [requests_token_example.py](requests_token_example.py)
This example program connects into the decryption appliance and lists all of the
available system health statuses using a user provided Authorization Token.
The Authentication Token may be created within the ETO WebUI User Settings.
An example of the program output is shown below.

> \$ python requests_token_example.py -s https://*decrypt-1*/api/ -t *7bc0b3e9a1c0c6eeb0c4cf0c13dbbbcc00965c71*
datapath: working
curator: working
backend: working
db: good
elasticsearch: working
platform: working
policy.warnings: good
policy.categories: good
license: good
license.exceeded: good
tasks.background: good
tasks.scheduled: good
disk.usage: good
memory.virtual: good
cpu.percent: good
user.passwords: good

## [requests_pki_create_example.py](requests_pki_create_example.py)
This example allows for a user to upload a endpoint (known server) certificate
and key file to the ETO PKI store.
An example below shows the creation of a self signed certificate and key for website:
test.testsite.com that can be uploaded using the example script.

> \$ openssl req -new -x509 -days 365 -nodes -out keycert.pem -keyout keycert.pem -subj '/CN=test.testsite.com'

> $ python requests_pki_create_example.py -s https://*decrypt-1*/api/ -u *apiuser*  -p *C0mpl3xpw* -i keycert.pem
Certificate and key added to PKI store, cert details: test.testsite.com, Unknown (Unknown, Unknown) [a131f510...]
