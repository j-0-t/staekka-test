
# require 'test/lib/module_test'
# require './test/lib/module_test'

require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::SessionCaching-test',
                      'Description'   => ' This module will test Msf::Sessions::SessionCaching ',
                      'Author'        => ['jot'],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_get
    # session.start_cache
    it 'should fail: get non existing' do
      !session.cache.exists?('non existing')
    end
    it 'should be true: get foo' do
      session.cache.add('foo', 'bar')
      session.cache.exists?('foo')
    end
    it 'should get foo' do
      out = session.cache.read('foo')
      out == 'bar'
    end
    it 'should delete foo' do
      session.cache.delete('foo')
      !session.cache.exists?('foo')
    end
  end
end
