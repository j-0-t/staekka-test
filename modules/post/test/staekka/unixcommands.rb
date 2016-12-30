# Advanced Post Exploitation
# require 'test/lib/module_test'
require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'
require 'msf/core/post/file'
require 'core/post/unix/commands'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'staekka_path'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Staekka
  # include Msf::Post::Staekka::File
  include Msf::Post::Unix::Commands
  # include Msf::StaekkaTest

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::Unix::Commands-test',
                      'Description'   => ' This module will test Msf::Sessions::Unix::Commands ',
                      'Author'        => ['jot'],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_unixcommands
    staekka_path =  ENV['STAEKKA_TEST']
    if staekka_path.nil?
      raise "Need a test directory containing a file for this testing option (export STAEKKA_TEST=...)"
    end

    it 'should change to the default directory' do
      cmd_exec("cd #{staekka_path}")
    end
    it 'should be in the default directory' do
      cmd_exec('pwd').to_s.match("staekka")
    end
    it 'should do uname' do
      uname
    end
    it 'should do uname (now cached)' do
      uname
    end
    session.cache.delete('uname')
    testdir = '/tmp/'
    it "should mkdir #{testdir}/foo/bar" do
      mkdir "#{testdir}/foo/bar"
      cmd_success?("test -d #{testdir}/foo/bar")
    end
    it "should delete  #{testdir}/foo/bar" do
      rm "#{testdir}/foo/bar"
      !cmd_success?("test -d #{testdir}/foo/bar")
    end
    it "should touch #{testdir}/foo_bar" do
      touch "#{testdir}/foo_bar"
      cmd_success?("test -f #{testdir}/foo_bar")
    end
    it "should delete  #{testdir}/foo_bar" do
      rm "#{testdir}/foo_bar"
      !cmd_success?("test -f #{testdir}/foo_bar")
    end
    it "should copy /etc/passwd  #{testdir}/cp1" do
      cp('/etc/passwd', "#{testdir}/cp1")
      cmd_success?("test -f #{testdir}/cp1")
    end
    it "should mv #{testdir}/cp1 #{testdir}/mv1 " do
      mv("#{testdir}/cp1", "#{testdir}/mv1")
      !cmd_success?("test -f #{testdir}/cp1")
    end
    it "should mv #{testdir}/cp1 #{testdir}/mv1 2" do
      cmd_success?("test -f #{testdir}/mv1")
    end
    rm "#{testdir}/mv1"
    it 'should cat /etc/passwd' do
      out = cat '/etc/passwd'
      out.match('root:')
    end
    it 'should grep in out' do
      out = cat '/etc/passwd'
      grep('root:', string: out)
    end
    it 'should grep in command' do
      grep('root:', cmd: 'cat /etc/passwd')
    end
    it 'should grep in file' do
      grep('root:', file: '/etc/passwd')
    end
    # it "should grep true" do
    #	grep("root:", {:file =>"/etc/passwd", true}) == true
    # end
    it 'should detect a compiler' do
      compiler?
    end
    it 'should detect a compiler and verify it' do
      compiler?(true)
    end
    it 'should detect bash as installed tool' do
      installed?('bash')
    end
    it 'should not detect nosuchtool as installed tool' do
      !installed?('nosuchtool')
    end
    it 'should detect ls as /bin/ls' do
      installed?('ls') == '/bin/ls'
    end
  end
end
