import unittest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from app import app
import threading
import time


class TestUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start Flask app in a separate thread
        cls.server = threading.Thread(target=cls.run_app)
        cls.server.daemon = True
        cls.server.start()

        # Give the server time to start
        time.sleep(1)

        # Configure Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        cls.driver = webdriver.Chrome(options=chrome_options)
        cls.base_url = "http://localhost:5000"

    @classmethod
    def run_app(cls):
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

    def test_registration_flow(self):
        self.driver.get(f"{self.base_url}/")

        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "form"))
        )

        # Fill form
        self.driver.find_element(By.NAME, "name").send_keys("Selenium User")
        self.driver.find_element(By.NAME, "voter_id").send_keys("sel123")
        self.driver.find_element(
            By.NAME, "community").send_keys("Remote Community A")
        self.driver.find_element(By.TAG_NAME, "form").submit()

        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located(
                (By.XPATH, "//*[contains(text(), 'Registration Successful')]"))
        )

        # Verify success
        self.assertIn("Registration Successful", self.driver.page_source)

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()


if __name__ == '__main__':
    unittest.main()
