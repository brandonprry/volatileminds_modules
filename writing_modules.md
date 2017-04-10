# Writing High-Quality Metasploit Modules

High quality Metasploit modules bring all the power of the Metasploit framework to the fingertips of the console user. Ensuring that data collected is stored correctly and efficiently is very important.

Getting Started
-
Standard empty module templates are included in the root of the project for exploits, scanners, brute force, and auxiliary modules. These should provide a jump start to module development.

Finished modules should also pass an `msftidy` run. `msftidy` is a tool shipped with the framework that looks for common problems in Metasploit modules.

Example:
```
$ ruby tools/dev/msftidy.rb ~/modules/auxiliary/scanner/citrix_xenmobileserver_scanner.rb 
```

Exploit modules
--
Exploit modules should call `report_vuln` when finished to ensure the vulnerability and host are saved to the database.

Example usage:
```
report_vuln(
  host: host,
  port: rport,
  proto: 'tcp',
  name: 'Wordpress FooBar 2.1 catid SQL Injection',
  refs: [['CVE', '2017-1029']]
)
```

Bruteforce modules
--
Bruteforce modules that find new credentials should add the credential to the database with `create_credential_login`. This will also create a host and service if service details are included. VolatileMinds brute force modules will be a little different from other brute force modules in the Metasploit framework. Our brute force modules are self-contained LoginScanners, whereas LoginScanner modules in the tree are split across multiple files.

Example usage:

```
def report_cred(username, password)
  service_data = {
    address: rhost,
    port: rport,
    service_name: ssl ? 'https' : 'http',
    protocol: 'tcp',
    workspace_id: myworkspace_id
  }

  credential_data = {
    module_fullname: self.fullname,
    origin_type: :service,
    username: username,
    private_data: password,
    private_type: :password
  }.merge(service_data)
 
  credential_core = create_credential(credential_data)

  login_data = {
    core: credential_core,
    last_attempted_at: DateTime.now,
    status: Metasploit::Model::Login::Status::SUCCESSFUL
  }.merge(service_data)
 
  create_credential_login(login_data)
end
```

Scanner modules
--
Scanner modules that find new hosts need to report both the host discovered and the service discovered with `report_service`.

Example usage:

```
report_service(
  :host => ip,
  :port => rport,
  :name => 'Wordpress FooBar 2.0 Plugin', 
  :info => 'Wordpress instance with the FooBar 2.0 plugin installed'
)
```

Auxiliary modules
--
Auxiliary modules should report the host they attempt to exploit, the application that is exploited, and any credentials or passwords hashes that are gathered during exploitation with `report_host`, `report_service`, and `create_credential_login`.

For storing password hashes pulled from the database that aren't useful credentials themselves, you can store them as nonreplayable hashes. This allows us to attempt cracking later by easily separating hashes from passwords.

Example usage:

```
def report_cred(opts)
  service_data = {
    address: opts[:ip],
    port: opts[:port],
    service_name: opts[:service_name],
    protocol: 'tcp',
    workspace_id: myworkspace_id
  }

  credential_data = {
    origin_type: :service,
    module_fullname: fullname,
    username: opts[:user],
    private_data: opts[:password],
    private_type: :nonreplayable_hash,
    jtr_format: 'mysql,mysql-sha1'
  }.merge(service_data)
 
  login_data = {
    core: create_credential(credential_data),
    status: Metasploit::Model::Login::Status::UNTRIED,
    proof: opts[:proof]
  }.merge(service_data)
 
  create_credential_login(login_data)
end
```
