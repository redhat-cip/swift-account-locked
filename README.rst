:Author: Chmouel Boudjnah
:Maintainer: Chmouel Boudjnah <chmouel@enovance.com>
:Issues: https://github.com/enovance/swift-account-locked/issues
:Source Code: https://github.com/enovance/swift-account-locked
:License: Apache
:Version: 0.1

====================
Swift Locked account
====================

A middleware that selectively allow/disallow to upload files using a header.

Assuming you have the header X-Account-Meta-Locked (this is configurable) set to `on`, `1`, `t`, `yes` the account will not be disallowed to upload files.

The header itself is by default not protected you will need to use the middleware `swift-control-headers <https://github.com/enovance/swift-control-headers>`_ to protect the value.


*******
Install
*******
1.  Install the two middlewares with pip (or using python-stdeb for debian)
::
  
  pip install https://github.com/enovance/swift-control-headers/zipball/master
  pip install https://github.com/enovance/swift-account-locked/zipball/master

2. Add control_headers and account_locked inside your proxy pipeline from the **proxy-server.conf** file
::

   [pipeline:main]
   pipeline = catch_errors healthcheck control_headers account_locked cache ratelimit  authtoken keystoneauth proxy-logging proxy-server

3. Configure the *control_headers* middleware to allow the admin user to read and write the locked header but not for anyone else
::

  [filter:control_headers]
  use = egg:swift_control_headers#control_headers
  header_locked = *=-,admin:admin=rw

4. Configure our middleware to lock the account when he sees the variable header locked defined to yes (or 1 or on etc..).
::

  [filter:account_locked]
  use = egg:swift_account_locked#account_locked
  locked_header = locked
  # recheck_account_existence = 60
  # denied_methods = PUT, DELETE, POST

*****
Usage
*****

Assuming the configuration above you would use the admin user to lock or unlock and account. You would need to have the **ResellerAdmin** capability (or role for keystone) to do that.  Using the token from the admin you connect to the user account and update the header to off or on.

For example I have a script available `here <http://p.chmouel.com/ksas>`_ that would connect with the user admin and get the url of the demo user to give you.
::

  -$ curl -O http://p.chmouel.com/ksas
  -$ bash ksas admin:admin:password demo:demo:password 127.0.0.1

gives me.
::

  curl -H 'X-Auth-Token: 07c31f4b9e764ebba628509d87907394' http://172.16.129.128:8080/v1/AUTH_e8f1fa83c05b4e0e8c48fac3d0a7dfeb

I can then use that to update the header to locked
::

  -$ curl -H 'X-Auth-Token: 07c31f4b9e764ebba628509d87907394' http://172.16.129.128:8080/v1/AUTH_e8f1fa83c05b4e0e8c48fac3d0a7dfeb -H 'X-Account-Meta-Locked: on'

and this effectively disallow uploading files.
::

  -$ swift -A http://127.0.0.1:5000/v2.0 -V2 -U demo:demo -K password upload foo /etc/issue
  Error trying to create container 'foo': 403 Forbidden: <html><h1>Forbidden</h1><p>Access was denied to this resource
  Object PUT failed:   
  [...]
