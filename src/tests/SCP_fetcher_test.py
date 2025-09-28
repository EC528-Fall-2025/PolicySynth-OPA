import unittest
from unittest.mock import Mock
from src.services.SCP_fecther import SCPFetcher
from src.models.SCP import SCP



class TestSCPFetcher(unittest.TestCase):

    def test_fetch_scp_returns_list(self):
        """Test that fetch_scp returns a list when successful."""
        # you'll need to have aws credentials set up to run this test locally
        fetcher = SCPFetcher()
        result = fetcher.fetch_scp()

        self.assertIsInstance(result, list)
        if result:
            self.assertIsInstance(result[0], SCP)

    def test_empty_policies_list(self):
        """Test behavior when AWS returns no policies."""
        mock_client = Mock()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Policies': []}]
        mock_client.get_paginator.return_value = mock_paginator

        fetcher = SCPFetcher(organizations_client=mock_client)
        result = fetcher.fetch_scp()

        self.assertEqual(result, [])
