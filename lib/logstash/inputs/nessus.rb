require "logstash/inputs/base"
require "rexml/document"
require "socket"
require "webrick" # http server

class LogStash::Inputs::Nessus < LogStash::Inputs::Base
  config_name "nessus"
  
  # HTTP port for receiving .nessus files
  config :port, :validate => :number, :default => 5055

  public
  def register
    @host = Socket.gethostname
    @logger.info("Nessus HTTP plugin is running on port #{@port}...")
  end

  public
  def run(queue)
    @logger.info("Nessus HTTP plugin is running. Waiting for files...")

    server = WEBrick::HTTPServer.new(:Port => @port)

    server.mount_proc '/' do |req, res|
      begin
        @logger.info("Received Nessus file via HTTP")

        # Log the first 500 characters to confirm receipt
        @logger.info("First 500 chars of Nessus file: #{req.body[0..500]}")

        # Parse the XML body
        xml_doc = REXML::Document.new(req.body)
        
        # Log XML root element for confirmation
        @logger.info("XML root element: #{xml_doc.root.name}")

        # Process file
        parse_nessus_file(xml_doc, queue)

        res.body = "File received and processed"
      rescue => e
        @logger.error("Failed to process file via HTTP: #{e.message}")
        res.body = "Error processing file"
      end
    end

    trap("INT") { server.shutdown }
    server.start
  end

  private
  def parse_nessus_file(xml_doc, queue)
    @logger.info("Parsing Nessus file...")

    xml_doc.elements.each("NessusClientData_v2/Report/ReportHost") do |host_element|
      @logger.info("Found ReportHost: #{host_element.attributes["name"]}")

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

      @logger.info("Successfully processed Nessus file")
    end
  end
end
