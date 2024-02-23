# Mira REST API - Python Bravado examples

## API Usage

After connecting and receiving a swagger client object from Bravado, the REST API
can be accessed in this format:

> result = client.<resource>.<method>(<param>, ...).response().result

When the API call has a request body (swagger model) it should be passed as parameter
named data. The class can be looked up with:

> client.get_model(<model>)

or alternatively a normal python dictionary can be passed.

Please refer to the “System” => “Development” swagger page in the web ui for details about
available resources, methods, parameters and models.

## [bravado_access_example.py](bravado_access_example.py)

This example connects into the appliance using the specified hostname, username and
password. Once successfully authenticated, the script can perform the following
actions as defined in the arguments

 - **‘users’** - list all the users on the appliance
 - **‘policy’** - create a new internal CA, policy, rulelist and corresponding segment. This segment will also be activated.
 - **‘backup-restore’** - Create a full backup of the appliance and download and store the backup file to the local directory as temp.zip, the backup will also be restored to the system
 - **‘all’** - perform all of the above actions

The bravado and pem libraries are needed.

> pip install -r requirements.txt

Note: This Bravado example requires a Mira appliance running version
2.1.0-2024.01.29-4096 or later.

An example of the program running is shown below.
> $ python bravado_access_example.py -s https://*decrypt-1*/api -u *apiuser* -p *C0mpl3xpw#* **all**
>
> apiuser: Jack Restitt <developer@org.com> \
> admin:   <admin@example.com>
>
> policy added: http://ntd-backend:8000/policies/2/ \
> segment added: http://ntd-backend:8000/segments/2/ \
> activation progress: 33.3333333333333% \
> activation completed: {"result": true, "message": "Activated: segment: 7315726a-a4b6-439b-8b20-2e3e2ff409a6\n", "activation_id": "94ba90db4e2843358a50ea6eed229907", "activated_segments": [2], "reactivated_segments": [], "deactivated_segments": []}
>
> backup progress: 86.6666666666667% \
> backup completed: {"message": "Backup archive generated.", "url": "/downloads/backups/f22cddd4f6c0e4ef296bb2ed27088044dfd4886f/mira-backup-2022-08-01-17-39-29-decrypt-1-2.0.0-3009.zip", "password": "e2389c22885e4f5a96823c19c8e77db9"}backed up to: ./temp.zip
>
> deactivation progress: 90.0% \
> deactivation completed: {"result": true, "message": "Deactivated: segment: 083d57c1-60dd-4354-b621-73b72209dbe5\n", "activation_id": "d00a811eac064ce8a0851c0ee315a0b2", "activated_segments": [], "reactivated_segments": [], "deactivated_segments": [2]} \
> restore progress: 0.0% \
> restore completed: {"message": "Restore successful: Policy/PKI: Installed 38 object(s) from 1 fixture(s).\nDefault PKI External CA state updated. Default PKI settings updated.\nManagement PKI Settings updated."} \
> restored: Restore Backup Archive \
> Restore successful: Policy/PKI: Installed 38 object(s) from 1 fixture(s). \
> Default PKI External CA state updated. Default PKI settings updated. \
> Management PKI Settings updated.

Note: an optional --noverify argument can be used to allow access to untrusted
self signed WebUI certificates, however this is not recommended for accessing
production systems, instead the WebUI appliance cert should be signed by a
trusted internal CA and verification always performed.
