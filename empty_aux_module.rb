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
      'Name'           => 'Empty Auxiliar Module',
      'Description'    => %q{
    This is a descrption for an auxiliary module. Also lists
    the version tested.
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => ''
    ))

    register_options(
      [
        #OptString.new("TARGETURI", [true, 'The relative URI', '/']),
      ], self.class)
  end

  def check
    Msf::Exploit::CheckCode::Safe
  end

  def run
  end
end

