#
#
require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

# require 'test/lib/module_test'
require 'core/post/staekka'
require 'staekka_path'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::ModuleTest::PostTest
  # include Msf::StaekkaTest
  include Msf::Post::Staekka
  include Msf::Staekka

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::Updatedb-test',
                      'Description'   => ' This module will test Msf::Sessions::Updatedb ',
                      'Author'        => ['jot'],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_updatedb
    session.updatedb = nil
    staekka_path =  ENV['STAEKKA_TEST']
    if staekka_path.nil?
      raise "Need a test directory containing a file for this testing option (export STAEKKA_TEST=...)"
    end


    it 'should change to the default directory' do
      cmd_exec("cd #{staekka_path}")
    end
    it 'should be in the default directory' do
      cmd_exec('pwd').match("staekka")
    end
    it 'should fail: updatedb exists' do
      !session.locate_updatedb?
    end
    rootdir = '/CHROOT/gentoo/x86/'
    it "starting updatedb on #{rootdir}" do
      session.locate_updatedb(rootdir)
    end
    it 'now it should be true ' do
      session.locate_updatedb?
    end
    it 'should fail: updatedb exists' do
      session.updatedb = nil
      !session.locate_updatedb?
    end
    # using an existing file for the fast tests
    rootdir = '/'

    updatedb_file = staekka_path + '/data/files/updatedb-2'
    it "starting cached updatedb on #{rootdir} using #{updatedb_file}" do
      session.locate_updatedb(rootdir, updatedb_file)
    end
    # session.updatedb = nil
    it 'updatedb_file_exists? existing file' do
      session.updatedb_file_exists?('/etc/passwd')
    end
    it 'updatedb_file_exists? existing directory' do
      session.updatedb_file_exists?('/etc')
    end
    it 'updatedb_file_exists? non existing file' do
      !session.updatedb_file_exists?('/etc/XXXXXXXX')
    end
    it 'updatedb_dir_exists? existing directory' do
      session.updatedb_dir_exists?('/etc')
    end
    it 'updatedb_dir_exists? existing file' do
      !session.updatedb_dir_exists?('/etc/passwd')
    end
    it 'updatedb_dir_exists? non existing directory' do
      !session.updatedb_dir_exists?('/xxxxxxxxxxxxxxx')
    end
    it 'updatedb_ls ls a file' do
      # puts "___/etc/shadow___#{session.updatedb_file_ls("/etc/shadow")}"
      session.updatedb_file_ls('/etc/shadow').to_s.match(/-rw-[-|r]-----/)
    end
    it 'updatedb_user owner of a file' do
      session.updatedb_file_user('/etc/shadow').to_s.match(/root/)
    end
    it 'updatedb_user group owner of a file' do
      session.updatedb_file_group('/etc/shadow').to_s.match(/root/)
    end
    it 'updatedb_user owner of a file?' do
      session.updatedb_file_user?('/etc/shadow', 'root')
    end
    it 'updatedb_user owner of a file?' do
      !session.updatedb_file_user?('/etc/shadow', 'nobody')
    end
    it 'updatedb_group owner of a file?' do
      puts session.updatedb_file_group('/etc/shadow').inspect
      session.updatedb_file_group?('/etc/shadow', 'root')
    end
    it 'updatedb_group owner of a file?' do
      !session.updatedb_file_group?('/etc/shadow', 'nobody')
    end
    it 'updatedb_permissions of a file (octal)' do
      session.updatedb_file_permissions?('/etc/ssh/sshd_config', 600)
    end
    it 'updatedb_permissions of a file (octal)' do
      session.updatedb_file_permissions?('/bin/passwd', 4711)
    end
    it 'updatedb_permissions of a file (octal)' do
      session.updatedb_file_permissions?('/tmp', 1777)
    end
    it 'updatedb_permissions wrong of a file (octal)' do
      !session.updatedb_file_permissions?('/etc/passwd', 600)
    end
    it 'updatedb_permissions of a file (string) ' do
      session.updatedb_file_permissions?('/etc/ssh/sshd_config', '-rw-------')
    end
    it 'updatedb_permissions of a file (string) ' do
      session.updatedb_file_permissions?('/bin/passwd', '-rws--x--x')
    end
    it 'updatedb_permissions of a file (string) ' do
      session.updatedb_file_permissions?('/tmp', 'drwxrwxrwt')
    end
    it 'updatedb_permissions wrong of a file (string) ' do
      !session.updatedb_file_permissions?('/etc/passwd', '-rw-------')
    end

    it 'updatedb_search_suid should find suid files' do
      session.updatedb_search_suid.to_s.match('/bin/passwd')
    end
    it 'updatedb_search_suid should not find normal files' do
      !session.updatedb_search_suid.to_s.match('/bin/ls')
    end
    it 'updatedb_search_world_writeable should find a file' do
      session.updatedb_search_world_writeable.to_s.match('/tmp/lin1')
    end
    it 'updatedb_search_world_writeable should not find a non writeable  file' do
      !session.updatedb_search_world_writeable.to_s.match('/etc/passwd')
    end
    it 'updatedb_search should find a file' do
      session.updatedb_search('shadow').to_s.match('/etc/shadow')
    end
    it 'updatedb_search should find a file with a regex' do
      session.updatedb_search(/sh.d[o|O]w/).to_s.match('/etc/shadow')
    end
    it 'updatedb_search should not find a file' do
      !session.updatedb_search('xxxxxxxxxxxxxxxxx').to_s.match('/etc/shadow')
    end
  end
end
