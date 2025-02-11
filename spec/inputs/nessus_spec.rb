require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/nessus"

describe LogStash::Inputs::Nessus do
  let(:config) { { "port" => 5055 } }

  it "should receive HTTP POST requests and process Nessus files" do
    plugin = LogStash::Inputs::Nessus.new(config)
    plugin.register

    # Simulate receiving a .nessus file
    sample_event = plugin.receive("<NessusClientData_v2><Report></Report></NessusClientData_v2>")
    expect(sample_event).not_to be_nil
  end
end
