import json
import pytest
from analyzer import NetworkAnalyzer

# Load test configurations
with open("config.json", "r") as f:
    config_data = json.load(f)

class TestNetworkInfrastructure:
    """QA Automation Suite for Network Infrastructure Validation"""

    @pytest.mark.parametrize("mode", ["normal", "stress", "exploratory"]) # 'real' mode is in progress
    def test_network_retransmission_modes(self, mode):
        """
        Validates network retransmission rates against predefined thresholds
        for normal, stress, and real-world production traffic profiles.
        """
        # Retrieve configuration for the specific test execution mode
        mode_config = config_data["modes"].get(mode)
        if not mode_config:
            pytest.fail(f"Execution mode '{mode}' configuration missing from config.json")

        pcap_file = mode_config["pcap_path"]
        threshold = mode_config["retrans_threshold"]
        condition = mode_config["condition"]

        # Initialize analyzer module with target path
        tool = NetworkAnalyzer(pcap_path=mode_config["pcap_path"])
        
        # Analyze and extract network data
        report = tool.analyze_network_profile(user_mode=mode)

        if not report:
            pytest.fail("Analyzer engine failed to return execution metrics.")
        
        net_data = report["network_metrics"]
        retrans_rate = net_data["retransmission_rate_percent"]
    
        # Handle Assertions inside the test framework natively!
        test_passed = False
        try:
            if mode_config["condition"] == "less_than":
                assert retrans_rate < mode_config["retrans_threshold"]
            elif mode_config["condition"] == "greater_than_or_equal":
                assert retrans_rate >= mode_config["retrans_threshold"]
            
            assert net_data["is_clean_close"] is True, "TCP session failed graceful shutdown."
            test_passed = True
        finally:
            # Send results to telemetry database regardless of pass/fail state
            tool.push_metrics_to_grafana(user_mode=mode, is_passed=test_passed)
