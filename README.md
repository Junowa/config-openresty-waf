# config-openresty-waf

This role configures openresty-waf:

* Configure modsecurity
* Add virtual hosts configurations
* Add modsecurity exceptions

If you use certificates in your vhost configurations, provision them on your own before applying this role.

In order to apply your custom virtual hosts you need to define `custom_vhosts_config` variable in your playbook. Example:
```
custom_vhosts_config:
  - { "tool": "waf", "servername" : "waf-dev.thalesdigital.io", "certificate_directory" : "/etc/nginx/cert" }
```
