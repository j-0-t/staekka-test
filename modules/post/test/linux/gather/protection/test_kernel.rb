#
#

# require 'test/lib/module_test'
# require './test/lib/module_test'

require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)

require 'module_test'
# require 'modules_test_extra'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  # include Msf::ModuleTestExtra
  include Msf::Post::Common
  include Msf::SessionEvent

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'post/test/linux/gather/protection/kernel',
                      'Description'   => ' This module will test  post/test/linux/gather/protection/kernel',
                      'Author'        => ['jot'],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_load
    mod_name = 'post/linux/gather/protection/kernel'
    load_test_module(mod_name)
  end

  def test_grsecurity
    it 'RSBAC should be enabled' do
      @output.reset
      @mod.grsecurity?('The RBAC system is currently enabled')
      @output.buffer.match('enabled')
    end
    it 'RSBAC should be diabled' do
      @output.reset
      @mod.grsecurity?('The RBAC system is currently disabled')
      @output.buffer.match('disabled')
    end
    it 'RSBAC should be wrong' do
      @output.reset
      @mod.grsecurity?('xxxxxxxxxx')
      @output.buffer.match('wrong output')
    end
    it 'RSBAC should NOT be diabled' do
      @output.reset
      @mod.grsecurity?('The RBAC system is currently enabled')
      !@output.buffer.match('disabled')
    end
  end
end
