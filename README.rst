====================
Swift Locked account
====================

A middleware that selectively allow/disallow to upload files using a header.

Assuming you have the header X-Account-Meta-Locked (this is configurable) set to `on`, `1`, `t`, `yes` the account will not be disallowed to upload files.

The header itself is by default not protected you will need to use the middleware `swift-control-headers <https://github.com/enovance/swift-control-headers>`_ to protect the value.


Install
^^^^^^^

1) Install the two middlewares with pip (or using python-stdeb for debian)
::

  pip install https://github.com/enovance/swift-control-headers/zipball/master
  pip install https://github.com/enovance/swift-account-locked/zipball/master

2) Add control_headers and account_locked inside your proxy pipeline from the **proxy-server.conf** file
::

   [pipeline:main]
   pipeline = catch_errors healthcheck control_headers account_locked cache ratelimit  authtoken keystoneauth proxy-logging proxy-server

3) Configure the *control_headers* middleware to allow the admin user to read and write the locked header but not for anyone else
::

  [filter:control_headers]
  use = egg:swift_control_headers#control_headers
  header_locked = *=-,admin:admin=rw

4) Configure our middleware to lock the account when he sees the variable header locked defined to yes (or 1 or on etc..).
::

  [filter:account_locked]
  use = egg:swift_account_locked#account_locked
  locked_header = locked
  # recheck_account_existence = 60
  # denied_methods = PUT, DELETE, POST
