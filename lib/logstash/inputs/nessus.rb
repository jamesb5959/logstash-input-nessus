require "logstash/inputs/base"
require "rexml/document"
require "socket"
 
class LogStash::Inputs::Nessus < LogStash::Inputs::Base
  config_name "nessus"
 
  # Directory where .nessus files are located
  config :path, :validate => :string, :required => true
 
  # Polling interval in seconds
  config :interval, :validate => :number, :default => 10
 
  public
  def register
    @host = Socket.gethostname
    @files_processed = []
  end
 
  public
  def run(queue)
    while !stop?
      Dir.glob(File.join(@path, "*.nessus")).each do |file|
        next if @files_processed.include?(file)
 
        begin
          content = File.read(file)
          xml_doc = REXML::Document.new(content)
          parse_nessus_file(xml_doc, file, queue)
          @files_processed << file
        rescue => e
          @logger.error("Failed to process file #{file}: #{e.message}")
        end
      end
      sleep(@interval)
    end
  end
 
  private
  def parse_nessus_file(xml_doc, file, queue)
    xml_doc.elements.each("NessusClientData_v2/Report/ReportHost") do |host_element|
      event = LogStash::Event.new
      event.set("host", host_element.attributes["name"])
 
      vulnerabilities = []
      host_element.elements.each("ReportItem") do |item|
        vulnerabilities << {
          "plugin_id" => item.attributes["pluginID"],
          "plugin_name" => item.attributes["pluginName"],
          "severity" => item.attributes["severity"]
        }
      end
      event.set("vulnerabilities", vulnerabilities)
      decorate(event)
      queue << event
    end
    @logger.info("Processed file #{file}")
  end
end