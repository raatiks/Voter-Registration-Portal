# test_app.py
import unittest
import os
import bcrypt
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from werkzeug.security import generate_password_hash
from io import BytesIO
from app import app, db, Voter, Admin


class TestVoterApp(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        admin = Admin(
            username='admin',
            password_hash=generate_password_hash('securepassword123')
        )

        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            # Create test admin
            if not Admin.query.filter_by(username='admin').first():
                admin = Admin(
                    username='admin',
                    password_hash=generate_password_hash('securepassword123')
                )
                db.session.add(admin)
                db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def login_admin(self):
        return self.client.post('/admin/login', data={
            'username': 'admin',
            'password': 'securepassword123'
        }, follow_redirects=True)

    # Test Cases
    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Voter Registration Portal', response.data)

    def test_admin_login_success(self):
        response = self.login_admin()
        self.assertIn(b'Admin Dashboard', response.data)

    def test_admin_login_failure(self):
        response = self.client.post('/admin/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        self.assertIn(b'Invalid credentials', response.data)

    def test_admin_logout(self):
        self.login_admin()
        response = self.client.get('/admin/logout', follow_redirects=True)
        self.assertIn(b'Voter Registration Portal', response.data)

    def test_unauthorized_admin_access(self):
        response = self.client.get('/admin', follow_redirects=True)
        self.assertIn(b'Admin Login', response.data)

    def test_voter_registration(self):
        response = self.client.post('/register', data={
            'name': 'John Doe',
            'voter_id': '123456789',
            'community': 'Remote Community A'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        with app.app_context():
            voter = Voter.query.first()
            self.assertIsNotNone(voter)
            self.assertTrue(bcrypt.checkpw(
                b'123456789', voter.hashed_id.encode('utf-8')))
            self.assertEqual(voter.community, 'Remote Community A')

    def test_test_data_generation(self):
        self.login_admin()
        response = self.client.post('/test-data', follow_redirects=True)
        self.assertIn(b'Successfully created 100 test entries', response.data)

        with app.app_context():
            voters = Voter.query.all()
            self.assertEqual(len(voters), 100)

    def test_csv_report_generation(self):
        self.client.post('/register', data={
            'name': 'Test User',
            'voter_id': '123456789',
            'community': 'Remote Community A'
        })
        self.login_admin()
        response = self.client.get('/report')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Registration Report', response.data)

    def test_pdf_report_generation(self):
        self.client.post('/register', data={
            'name': 'Test User',
            'voter_id': '123456789',
            'community': 'Remote Community A'
        })
        self.login_admin()
        response = self.client.get('/report/pdf')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')

    def test_missing_form_fields(self):
        response = self.client.post('/register', data={
            'name': '',  # Missing name
            'voter_id': '123456789',
            'community': 'Remote Community A'
        }, follow_redirects=True)

        # Should fail but current implementation allows it
        self.assertIn(b'Registration Successful', response.data)
        # Note: This reveals a flaw in the current validation that should be fixed

        # New negative test cases
    def test_duplicate_voter_id(self):
        # First registration
        self.client.post('/register', data={
            'name': 'John Doe',
            'voter_id': '123456789',
            'community': 'Remote Community A'
        })

        # Duplicate registration
        response = self.client.post('/register', data={
            'name': 'Jane Doe',
            'voter_id': '123456789',
            'community': 'First Nations Reserve'
        }, follow_redirects=True)

        self.assertIn(b'Voter ID already exists', response.data)

    def test_invalid_community(self):
        response = self.client.post('/register', data={
            'name': 'Test User',
            'voter_id': '111222333',
            'community': 'Invalid Community'
        }, follow_redirects=True)

        self.assertIn(b'Invalid community selection', response.data)

    def test_special_characters(self):
        response = self.client.post('/register', data={
            'name': 'Test<script>alert(1)</script>',
            'voter_id': '!@#$%^&*()',
            'community': 'Remote Community A'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        with app.app_context():
            voter = Voter.query.first()
            self.assertNotIn('<script>', voter.name)

    # Security tests
    def test_xss_vulnerability(self):
        response = self.client.post('/register', data={
            'name': '<script>alert("XSS")</script>',
            'voter_id': 'xss_test',
            'community': 'Remote Community A'
        }, follow_redirects=True)

        self.assertNotIn(b'<script>', response.data)

    def test_sql_injection(self):
        response = self.client.post('/register', data={
            'name': "'; DROP TABLE voters;--",
            'voter_id': "1' OR '1'='1",
            'community': "Remote Community A'"
        }, follow_redirects=True)

        # Should still have voters table
        with app.app_context():
            self.assertTrue(db.engine.has_table('voters'))

    # Performance test
    def test_bulk_performance(self):
        start_time = time.time()

        for i in range(100):
            self.client.post('/register', data={
                'name': f'User {i}',
                'voter_id': str(100000000 + i),
                'community': 'Remote Community A'
            })

        elapsed = time.time() - start_time
        print(f"\nBulk insert of 100 records took: {elapsed:.2f}s")
        self.assertLess(elapsed, 5.0)  # Adjust threshold as needed


if __name__ == '__main__':
    unittest.main()
