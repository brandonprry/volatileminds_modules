require 'digest'

module Msf
class Plugin::VolatileMinds < Msf::Plugin
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      'VolatileMinds'
    end

    def commands
      {
        'vm_login' => 'Login with your VolatileMinds credentials',
      }
    end

    def cmd_vm_login(*args)
      print_good("hello")
    end

  end

  def initialize(framework, opts)
    super
    print_status("VolatileMinds plugin loaded. Log in with your VolatileMinds credentials.")
  end

  def cleanup
    remove_console_dispatcher('VolatileMinds')
  end

  def name
    'VolatileMinds'
  end

  def desc
    'Integrate Metasploit with your VolatileMinds account'
  end
end
end
