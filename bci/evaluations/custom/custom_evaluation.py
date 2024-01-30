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
        page_folder_path = Global.custom_page_folder
        project_names = [name for name in os.listdir(page_folder_path) if os.path.isdir(os.path.join(page_folder_path, name))]
        for project_name in project_names:
            # Find tests in folder
            project_path = os.path.join(page_folder_path, project_name)
            self.tests_per_project[project_name] = {}
            for test_name in os.listdir(project_path):
                url_queue_file_path = os.path.join(project_path, test_name, 'url_queue.txt')
                if os.path.isfile(url_queue_file_path):
                    # If an URL queue is specified, it is parsed and used
                    with open(url_queue_file_path) as file:
                        self.tests_per_project[project_name][test_name] = file.readlines()
                        self.tests[test_name] = self.tests_per_project[project_name][test_name]
                else:
                    # Otherwise, a default URL queue is used, based on the domain that hosts the main page
                    test_folder_path = os.path.join(project_path, test_name)
                    for domain in os.listdir(test_folder_path):
                        main_folder_path = os.path.join(test_folder_path, domain, 'main')
                        if os.path.exists(main_folder_path):
                            self.tests_per_project[project_name][test_name] = [
                                f'https://{domain}/{project_name}/{test_name}/main',
                                'https://a.test/report/?leak=baseline'
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
            result = {
                'requests': collector.requests
            }
            is_wpt = len(collector.requests) > 0 and "wpt_result" in collector.requests[0]

        logger.debug(f'collector requests = {collector.requests}')

        return params.create_test_result_with(browser_version, binary_origin, result, is_dirty, is_wpt)

    def get_mech_groups(self, project=None):
        if project:
            return sorted(self.tests_per_project[project].keys())
        return sorted(self.tests_per_project.keys())

    def get_projects(self) -> list[str]:
        return sorted(list(self.tests_per_project.keys()))
