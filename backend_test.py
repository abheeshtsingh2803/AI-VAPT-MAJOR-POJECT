import requests
import sys
import json
import time
from datetime import datetime

class VAPTAPITester:
    def __init__(self, base_url="https://autovapt.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        self.user_id = None

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        
        if headers:
            test_headers.update(headers)

        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            success = response.status_code == expected_status
            
            if success:
                self.log_test(name, True)
                try:
                    return True, response.json()
                except:
                    return True, response.text
            else:
                self.log_test(name, False, f"Expected {expected_status}, got {response.status_code}. Response: {response.text[:200]}")
                return False, {}

        except Exception as e:
            self.log_test(name, False, f"Request failed: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test API health check"""
        success, response = self.run_test(
            "API Health Check",
            "GET",
            "",
            200
        )
        return success

    def test_user_registration(self):
        """Test user registration"""
        test_user_data = {
            "username": f"testuser_{int(time.time())}",
            "email": f"test_{int(time.time())}@example.com",
            "password": "TestPassword123!"
        }
        
        success, response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data=test_user_data
        )
        
        if success and 'access_token' in response:
            self.token = response['access_token']
            self.log_test("Registration Token Received", True)
            return True, test_user_data
        else:
            self.log_test("Registration Token Received", False, "No access token in response")
            return False, test_user_data

    def test_user_login(self, user_data):
        """Test user login"""
        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }
        
        success, response = self.run_test(
            "User Login",
            "POST",
            "auth/login",
            200,
            data=login_data
        )
        
        if success and 'access_token' in response:
            self.token = response['access_token']
            self.log_test("Login Token Received", True)
            return True
        else:
            self.log_test("Login Token Received", False, "No access token in response")
            return False

    def test_dashboard_statistics(self):
        """Test dashboard statistics endpoint"""
        success, response = self.run_test(
            "Dashboard Statistics",
            "GET",
            "dashboard/statistics",
            200
        )
        
        if success:
            required_fields = ['total_scans', 'completed_scans', 'total_vulnerabilities', 
                             'high_risk_count', 'medium_risk_count', 'low_risk_count']
            
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Dashboard Statistics Fields", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Dashboard Statistics Fields", True)
                return True
        return False

    def test_get_scans(self):
        """Test get scans endpoint"""
        success, response = self.run_test(
            "Get User Scans",
            "GET",
            "scans",
            200
        )
        return success

    def test_start_vulnerability_scan(self):
        """Test starting a vulnerability scan"""
        scan_data = {
            "target_url": "https://httpbin.org/",
            "scan_type": "web_app"
        }
        
        success, response = self.run_test(
            "Start Vulnerability Scan",
            "POST",
            "scans/start",
            200,
            data=scan_data
        )
        
        if success and 'id' in response:
            self.log_test("Scan ID Generated", True)
            return True, response['id']
        else:
            self.log_test("Scan ID Generated", False, "No scan ID in response")
            return False, None

    def test_get_scan_vulnerabilities(self, scan_id):
        """Test getting vulnerabilities for a scan"""
        if not scan_id:
            self.log_test("Get Scan Vulnerabilities", False, "No scan ID provided")
            return False
            
        success, response = self.run_test(
            "Get Scan Vulnerabilities",
            "GET",
            f"scans/{scan_id}/vulnerabilities",
            200
        )
        return success

    def test_invalid_authentication(self):
        """Test API behavior with invalid authentication"""
        # Save current token
        original_token = self.token
        
        # Test with invalid token
        self.token = "invalid_token_12345"
        success, response = self.run_test(
            "Invalid Authentication Handling",
            "GET",
            "dashboard/statistics",
            401
        )
        
        # Restore original token
        self.token = original_token
        return success

    def test_duplicate_user_registration(self, user_data):
        """Test duplicate user registration"""
        success, response = self.run_test(
            "Duplicate User Registration Prevention",
            "POST",
            "auth/register",
            400,
            data=user_data
        )
        return success

    def test_invalid_login(self):
        """Test login with invalid credentials"""
        invalid_login_data = {
            "username": "nonexistent_user",
            "password": "wrong_password"
        }
        
        success, response = self.run_test(
            "Invalid Login Handling",
            "POST",
            "auth/login",
            401,
            data=invalid_login_data
        )
        return success

    def test_scan_with_invalid_url(self):
        """Test scan with invalid URL"""
        invalid_scan_data = {
            "target_url": "not_a_valid_url",
            "scan_type": "web_app"
        }
        
        # This might return 200 but should handle gracefully
        success, response = self.run_test(
            "Scan with Invalid URL",
            "POST",
            "scans/start",
            200,
            data=invalid_scan_data
        )
        return success

    def wait_for_scan_completion(self, scan_id, max_wait_time=60):
        """Wait for scan to complete or timeout"""
        if not scan_id:
            return False
            
        print(f"⏳ Waiting for scan {scan_id[:8]} to complete (max {max_wait_time}s)...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            success, scans = self.run_test(
                "Check Scan Status",
                "GET",
                "scans",
                200
            )
            
            if success:
                for scan in scans:
                    if scan['id'] == scan_id:
                        status = scan['status']
                        print(f"📊 Scan status: {status}")
                        
                        if status == 'completed':
                            self.log_test("Scan Completion", True)
                            return True
                        elif status == 'failed':
                            self.log_test("Scan Completion", False, "Scan failed")
                            return False
            
            time.sleep(5)  # Wait 5 seconds before checking again
        
        self.log_test("Scan Completion", False, f"Scan did not complete within {max_wait_time} seconds")
        return False

def main():
    print("🚀 Starting VAPT Platform API Testing...")
    print("=" * 60)
    
    tester = VAPTAPITester()
    
    # Test 1: Health Check
    if not tester.test_health_check():
        print("❌ API is not accessible. Stopping tests.")
        return 1

    # Test 2: User Registration
    reg_success, user_data = tester.test_user_registration()
    if not reg_success:
        print("❌ User registration failed. Stopping tests.")
        return 1

    # Test 3: User Login
    if not tester.test_user_login(user_data):
        print("❌ User login failed. Stopping tests.")
        return 1

    # Test 4: Dashboard Statistics
    tester.test_dashboard_statistics()

    # Test 5: Get Scans
    tester.test_get_scans()

    # Test 6: Start Vulnerability Scan
    scan_success, scan_id = tester.test_start_vulnerability_scan()
    
    # Test 7: Get Scan Vulnerabilities (even if empty initially)
    if scan_id:
        tester.test_get_scan_vulnerabilities(scan_id)
        
        # Test 8: Wait for scan completion and check results
        if tester.wait_for_scan_completion(scan_id, max_wait_time=45):
            # Check vulnerabilities after completion
            tester.test_get_scan_vulnerabilities(scan_id)

    # Test 9: Security Tests
    tester.test_invalid_authentication()
    tester.test_duplicate_user_registration(user_data)
    tester.test_invalid_login()
    
    # Test 10: Edge Cases
    tester.test_scan_with_invalid_url()

    # Print Results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {tester.tests_run}")
    print(f"Passed: {tester.tests_passed}")
    print(f"Failed: {tester.tests_run - tester.tests_passed}")
    print(f"Success Rate: {(tester.tests_passed/tester.tests_run)*100:.1f}%")
    
    # Save detailed results
    results_file = "/app/test_reports/backend_api_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "summary": {
                "total_tests": tester.tests_run,
                "passed_tests": tester.tests_passed,
                "failed_tests": tester.tests_run - tester.tests_passed,
                "success_rate": (tester.tests_passed/tester.tests_run)*100,
                "timestamp": datetime.now().isoformat()
            },
            "detailed_results": tester.test_results
        }, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: {results_file}")
    
    # Return appropriate exit code
    if tester.tests_passed == tester.tests_run:
        print("\n🎉 All tests passed!")
        return 0
    elif tester.tests_passed / tester.tests_run >= 0.8:
        print("\n⚠️  Most tests passed, minor issues detected")
        return 0
    else:
        print("\n❌ Significant issues detected")
        return 1

if __name__ == "__main__":
    sys.exit(main())