##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Empty Post Module',
        'Description'   => %q{
          },
        'License'       => 'VolatileMinds',
        'Author'        => [ ''],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ]
      ))
  end

  def run
  end
end
