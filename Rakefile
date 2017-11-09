require './website_importer.rb'
task :kickoff_python do
    WebsiteImporter.new.import
    exec("python catch_phishing.py")
end

# require 'timeout'
# require 'open3'
#random stuff:
# Open3.popen3('python catch_phishing.py') do |_, stdout_and_stderr, _|
#   # puts stdout.read
#   # puts stderr.read
#   stdout_and_stderr.each do |line|
#     puts line
#   end
# end
