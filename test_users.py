# /test_billsapi.py
import unittest
from unittest.mock import patch
import json, os, uuid
from src.app import create_app, db

class BillsAPITestCase(unittest.TestCase):
    """This class represents the billsapi test cases"""
    def setUp(self):
        """Defines test variables and initializes app"""
        self.app = create_app("testing") # initializes app with testing environment variable
        self.client = self.app.test_client # initialized test client
        with self.app.app_context():    # binds the app to the current context
            db.create_all() # create all tables

    def test_api_can_get_all_users(self):
        """Test API can get a user list (GET request)."""
        list_users_request = self.client().get('/v1/user/all')
        self.assertEqual(list_users_request.status_code, 200)
        self.assertIn('Wiley', str(list_users_request.data))
        # print(str(list_users_request.data))

# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()
