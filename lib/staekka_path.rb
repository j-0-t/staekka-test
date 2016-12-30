module Msf
	module StaekkaTest
		def staekka_path
			#File.realpath (File.dirname(__FILE__) + '/../../')
			File.realpath @staekka_path
		end
    def staekka_test_path
      File.realpath @staekka_test_path
    end
	end
end
