import json
import operator
import pytest
from analyzer import NetworkAnalyzer, PROJECT_ROOT

# Load test configurations (resolved relative to this file, so pytest runs from any directory)
with open(PROJECT_ROOT / "config.json", "r") as f:
    config_data = json.load(f)

CONDITIONS = {
    "less_than": operator.lt,
    "greater_than_or_equal": operator.ge,
}

class TestNetworkInfrastructure:
    """QA Automation Suite for Network Infrastructure Validation"""

    @pytest.mark.parametrize("mode", list(config_data["modes"]))
    def test_network_retransmission_modes(self, mode):
        """
        Validates network retransmission rates against predefined thresholds
        for normal, stress, exploratory (fuzzed) and real-world production traffic profiles.
        """
        # Retrieve configuration for the specific test execution mode
        mode_config = config_data["modes"][mode]
        pcap_file = PROJECT_ROOT / mode_config["pcap_path"]
        condition = mode_config["condition"]

        if not pcap_file.exists():
            if mode == "real":
                pytest.skip("No live capture found. Run './run_tests.sh real' to record one.")
            pytest.fail(f"Capture '{pcap_file}' missing. Run the mock generation scripts first.")

        # Initialize analyzer module with target path
        tool = NetworkAnalyzer(pcap_path=pcap_file)

        # Analyze and extract network data
        report = tool.analyze_network_profile(user_mode=mode)

        if not report:
            pytest.fail("Analyzer engine failed to return execution metrics.")

        net_data = report["network_metrics"]
        retrans_rate = net_data["retransmission_rate_percent"]

        test_passed = False
        try:
            if condition == "matches_ground_truth":
                # Fuzzed captures: the analyzer must find exactly the anomalies that were injected
                truth = json.loads((PROJECT_ROOT / mode_config["ground_truth_path"]).read_text())
                replay = f"replay with: SEED={truth['seed']} ./run_tests.sh exploratory"
                assert net_data["total_retransmissions"] == truth["retransmissions"], \
                    f"Detected {net_data['total_retransmissions']} retransmissions, injected {truth['retransmissions']} ({replay})"
                assert net_data["out_of_order_segments"] == truth["out_of_order"], \
                    f"Detected {net_data['out_of_order_segments']} out-of-order segments, injected {truth['out_of_order']} ({replay})"
            else:
                compare = CONDITIONS.get(condition)
                if compare is None:
                    pytest.fail(f"Unknown condition '{condition}' for mode '{mode}'. Supported: {sorted(CONDITIONS)}")
                threshold = mode_config["retrans_threshold"]
                assert compare(retrans_rate, threshold), \
                    f"Retransmission rate {retrans_rate}% violates '{condition} {threshold}%' for mode '{mode}'"

            if mode_config.get("require_clean_close", True):
                assert net_data["is_clean_close"] is True, "TCP session failed graceful shutdown."
            test_passed = True
        finally:
            # Send results to telemetry database regardless of pass/fail state
            tool.push_metrics_to_pushgateway(user_mode=mode, is_passed=test_passed)
