import os
import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_nginx_is_installed(host):
    nginx = host.package('openresty')

    assert nginx.is_installed


def test_nginx_is_running(host):
    nginx = host.service('openresty')

    assert nginx.is_running


def test_nginx_is_enabled(host):
    nginx = host.service('openresty')

    assert nginx.is_enabled


def test_nginx_configuration_exists(host):
    nginx = host.file('/usr/local/openresty/nginx/conf/nginx.conf')

    assert nginx.exists


def test_modsecurity_is_loaded(host):
    modsec_load = host.run(
      'grep ngx_http_modsecurity_module \
        /usr/local/openresty/nginx/conf/nginx.conf')

    assert modsec_load.stdout.startswith("load_module")


def test_modsecurity_engine_is_on(host):
    modsec_conf = host.run(
      'grep SecRuleEngine /etc/nginx/modsec/modsecurity.conf')

    assert "on" in modsec_conf.stdout


def test_crs_config_is_loaded(host):
    crs_main_include = host.run(
      'grep /usr/local/owasp-modsecurity-crs-3.0.0/crs-setup.conf \
      /etc/nginx/modsec/main.conf')

    assert crs_main_include.stdout.startswith("Include")


def test_crs_ruleset_is_loaded(host):
    crs_ruleset_include = host.run(
      "grep '/usr/local/owasp-modsecurity-crs-3.0.0/rules/\*\.conf' \
      /etc/nginx/modsec/main.conf")

    assert crs_ruleset_include.stdout.startswith("Include")


def test_ddos_rules_exist(host):
    r_path = '/usr/local/owasp-modsecurity-crs-3.0.0/rules/'
    ddos = host.file(r_path+'REQUEST-912-DOS-PROTECTION.conf')

    assert ddos.exists


def test_logging_is_enabled(host):
    secauditlog_include = host.run(
      'grep /var/log/modsec_audit.log /etc/nginx/modsec/modsecurity.conf')

    assert secauditlog_include.stdout.startswith("SecAuditLog")


def test_transaction_logging_is_enabled(host):
    nginxlog_include = host.run(
      'grep /var/log/nginx/access.log \
        /usr/local/openresty/nginx/conf/nginx.conf')

    assert nginxlog_include.stdout.strip().startswith("access_log")


def test_exception_rule_file(host):
    myvars = host.ansible.get_variables()
    modsec_default_exception_file = myvars['modsecurity_excluded_rule_files']

    if modsec_default_exception_file:
        for exception_file in modsec_default_exception_file:
            r_path = '/usr/local/owasp-modsecurity-crs-3.0.0/rules/'
            myoldfile = host.file(r_path+exception_file)
            mynewfile = host.file(r_path+exception_file+'.disabled')
            assert mynewfile.exists
            assert not myoldfile.exists


def test_exception_rule_ids(host):

    myvars = host.ansible.get_variables()
    modsec_default_except_file = myvars['modsecurity_default_exception_file']
    modsec_excluded_rule_ids = myvars['modsecurity_excluded_rule_ids']

    rules_path = '/usr/local/owasp-modsecurity-crs-3.0.0/rules/'
    rules_path += modsec_default_except_file

    print rules_path

    if modsec_excluded_rule_ids:
        for rule_id in modsec_excluded_rule_ids:
            cmd = 'grep ' + rule_id + ' ' + rules_path
            grep_rule_id = host.run(cmd)
            assert grep_rule_id.stdout.startswith("SecRuleRemoveById")


def test_nginx_rotation_configuration_exists(host):
    nginx = host.file('/etc/logrotate.d/nginx')

    assert nginx.exists
