# Keystone originating IP aware password authentication extension

Keystone IPPassword is an Openstack keystone extenstion that enables
an IP ACL similar to those used in network equipment to be applied
to username/password login attempts to keystone.

The implementation is a Python class derived from the existing keystone
auth Password plugin that validates the username and originating IP against
a set of user defined rules. If the validation passes, the Password base
class implementation is called to perform the original username/password
authentication.

## Installation

Install with pip into the same python environment as the keystone service.

Validate the installation as follows by installing entry-point-inspector with pip:

```sh
(keystone-25.0.0.0rc2.dev12) root@aio1-keystone-container-75c83047:~/ipaddrauth# epi group show keystone.auth.password
+------------+--------------------------------+------------+----------------------+-------+
| Name       | Module                         | Member     | Distribution         | Error |
+------------+--------------------------------+------------+----------------------+-------+
| default    | keystone.auth.plugins.password | Password   | keystone 21.0.1.dev2 |       |
| ippassword | ipaddrauth.password            | IPPassword | ipaddrauth 0.0.0     |       |
+------------+--------------------------------+------------+----------------------+-------+
```

To work with Horizon a patch must be applied https://review.opendev.org/c/openstack/horizon/+/838859

## Configuration
```
An example of what is needed in keystone.conf to make this work

[auth]
methods = password,token,application_credential"

# override the password method to use the IPPassword implementation
password = ippassword

[ippassword]
# define an ordered ruleset to permit or deny usernames based on originating IP
# example allows any user on rfc1918 networks
          allows usernames starting "safe_admin_" from rfc1918 and a specified subnet (maybe these use TOTP)
          explicity denies the admin user from all other addresses
          implicity denies all other users who match no previous rules
rule = {"regex": ".*",           "action": "permit", "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] }
rule = {"regex": "^safe_admin_", "action": "permit", "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "1.2.3.0/24"] }
rule = {"regex": "admin",        "action": "deny",   "networks": ["0.0.0.0/0"] }

# set to False to allow all login attempts with a missing Forwarded or X-Forwarded-For header
# deny_if_no_forwarded = False
```


# Operation

- Rules defined in keystone.conf are evaulated in order
- The first rule which matches a permit or deny action takes effect
- If no rules match an implicit deny action applies
- If no headers indicating the originating IP are present the action is to deny login
