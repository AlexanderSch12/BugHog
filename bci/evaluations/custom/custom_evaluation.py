import logging
import os
import socket
from unittest import TestResult
from bci.browser.configuration.browser import Browser

from bci.configuration import Global
from bci.evaluations.custom.custom_mongodb import CustomMongoDB
from bci.evaluations.evaluation_framework import EvaluationFramework
from bci.evaluations.logic import TestParameters
from bci.http.collector import Collector

logger = logging.getLogger(__name__)
hostname = socket.gethostname()

class CustomEvaluationFramework(EvaluationFramework):

    db_class = CustomMongoDB

    def __init__(self):
        super().__init__()
        self.tests_per_project = {}
        self.tests = {}
        self.initialize_tests_and_url_queues()
        self.initialize_wpt_tests()


    def initialize_wpt_tests(self):
        wpt_path = "/home/test/web-platform-tests"
        if not os.listdir(wpt_path):
            return
        subject_name = "content-security-policy"
        subject_path =  os.path.join(wpt_path, subject_name)
        url = "http://web-platform.test:8000"
        url_subject = os.path.join(url,subject_name)
        for test_type in os.listdir(subject_path):
            test_type_path = os.path.join(subject_path, test_type)
            url_test_type = os.path.join(url_subject, test_type)
            if not os.path.isdir(test_type_path):
                continue
            project_name = "WPT CSP: " + test_type
            self.tests_per_project[project_name] = {}
            for test_file in os.listdir(test_type_path):
                if test_file.endswith('.html'):
                    url_test = os.path.join(url_test_type,test_file)
                    url_test = url_test +'?remote_ip=' + hostname
                    test_name = os.path.splitext(test_file)[0]
                    self.tests_per_project[project_name][test_name] = [url_test]
                    self.tests[test_name] = self.tests_per_project[project_name][test_name]
                    

    def initialize_tests_and_url_queues(self):
        used_test_names = {}
        page_folder_path = Global.custom_page_folder
        test_folder_path = Global.custom_test_folder
        if not os.path.isdir(test_folder_path):
            return
        project_names = [name for name in os.listdir(test_folder_path) if os.path.isdir(os.path.join(test_folder_path, name))]
        for project_name in project_names:
            # Find tests in folder
            project_path = os.path.join(test_folder_path, project_name)
            self.tests_per_project[project_name] = {}
            for test_name in os.listdir(project_path):
                if test_name in used_test_names:
                    raise AttributeError(f"Test name '{test_name}' should be unique over all projects (found in {project_name} and {used_test_names[test_name]})")
                used_test_names[test_name] = project_name
                test_path = os.path.join(project_path, test_name)
                if os.path.isdir(test_path):
                    with open(os.path.join(test_path, "url_queue.txt")) as file:
                        self.tests_per_project[project_name][test_name] = file.readlines()
                        self.tests[test_name] = self.tests_per_project[project_name][test_name]
            # Find remaining tests by checking the pages hosting tests
            project_path = os.path.join(page_folder_path, project_name)
            for test_name in os.listdir(project_path):
                test_path = os.path.join(project_path, test_name)
                for domain in os.listdir(test_path):
                    main_folder_path = os.path.join(project_path, test_path, domain, "main")
                    if os.path.exists(main_folder_path) and test_name not in used_test_names:
                        used_test_names[test_name] = project_name
                        self.tests_per_project[project_name][test_name] = [
                            f"https://{domain}/custom/{test_name}/main",
                            "https://adition.com/report/?leak=baseline"
                        ]
                        self.tests[test_name] = self.tests_per_project[project_name][test_name]


    def perform_specific_evaluation(self, browser: Browser, params: TestParameters) -> TestResult:
        logger.info(f'Starting test for {params}')
        browser_version = browser.version
        binary_origin = browser.get_binary_origin()

        collector = Collector()
        collector.start()

        is_dirty = False
        try:
            url_queue = self.tests[params.mech_group]
            for url in url_queue:
                tries = 0
                while tries < 3:
                    tries += 1
                    browser.visit(url)
        except Exception as e:
            logger.error(f'Error during test: {e}', exc_info=True)
            is_dirty = True
        finally:
            collector.stop()
            if not is_dirty:
                if len([request for request in collector.requests if 'report/?leak=baseline' in request['url']]) == 0:
                    is_dirty = True
            if 'wpt' in params.database_collection:
                    is_wpt = True
                    if not collector.requests:
                        collector.requests.append({
                            'url': 'undefined',
                            'wpt_result': 'Sanity check: no result received'
                            })
            result = {
                'requests': collector.requests
            }

        logger.debug(f'collector requests = {collector.requests}')

        return params.create_test_result_with(browser_version, binary_origin, result, is_dirty, is_wpt)

    def get_mech_groups(self, project=None):
        if project:
            return sorted(self.tests_per_project[project].keys())
        return sorted(self.tests_per_project.keys())

    def get_projects(self) -> list[str]:
        return sorted(list(self.tests_per_project.keys()))
