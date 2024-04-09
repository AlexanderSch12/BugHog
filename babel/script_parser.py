from bs4 import BeautifulSoup
import os
import subprocess
import logging

OUTPUT = '/home/ubuntu/BugHog/babel/output.js'
INPUT = '/home/ubuntu/BugHog/babel/input.js'
TOPIC = 'content-security-policy'

logger = logging.getLogger('script_parser')

def replace_script(url):
    if url.endswith('.js'):
        babel_convert_file(input_path = url, output_path = url)
        # browserify_convert_file(input_path = url, output_path = url)
    else:
        page = open(url,'r')
        try:
            soup = BeautifulSoup(page.read(), features="html.parser")
            page.close()
            for script in soup.findAll('script', {"src" : None}):
                babel_output = babel_convert_file(data = script.string)
                final_code = babel_output
                script.string = final_code
            page = open(url,'w')
            page.write(soup.prettify())
        except Exception as e:
            raise e
        finally:
            page.close()


def babel_convert_file(data=None, input_path = INPUT, output_path = OUTPUT):
    babel_command = [
        'npx',
        'babel',
        input_path
    ]

    if data is not None:
        input_file = open(input_path,"w")
        input_file.write(data)
        input_file.close()
    else:
        babel_command.extend(('--out-file', output_path))

    try:
        return subprocess.check_output(babel_command).decode("utf-8")
    except Exception as e:
        raise e


def browserify_convert_file(data = None, input_path = INPUT, output_path = OUTPUT):
    browserify_command = [
        'browserify',
        input_path
    ]

    if data is not None:
        input_file = open(input_path,"w")
        input_file.write(data)
        input_file.close()
    else:
        browserify_command.extend(('-o', output_path))

    try:
        return subprocess.check_output(browserify_command).decode("utf-8")        
    except Exception as e:
        raise e


def get_config():
    config_url = "babel.config.json"
    # try:
    #     config = open.(url)
    # except Exception as e:
    #     raise e

    return config_url

def crawl():
    wpt_path = "/home/ubuntu/wpt_babel1"
    if not os.listdir(wpt_path):
        return
    topic_name = TOPIC
    topic_path =  os.path.join(wpt_path, topic_name)

    for subtopic in os.listdir(topic_path):
        subtopic_path = os.path.join(topic_path, subtopic)
        if not os.path.isdir(subtopic_path):
            continue

        for root,dirs,files in os.walk(subtopic_path):
            for test_file in files:
                if test_file.endswith(".html") or test_file.endswith(".js"):
                    subsubtopic_list = root.split("/" + subtopic + "/")
                    subsubtopic = "" if len(subsubtopic_list) == 1 else subsubtopic_list[1]
                    path_test = os.path.join(subtopic_path, subsubtopic, test_file)
                    try:
                        replace_script(path_test)
                    except Exception as e:
                        logging.error(path_test)
                        logging.error(e)
                        continue


if __name__ == "__main__":
    logging.basicConfig(filename="errors.log",
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.ERROR)
    # crawl()
    replace_script("/home/ubuntu/wpt_babel1/content-security-policy/reporting/report-only-in-meta.sub.html")
    replace_script("/home/ubuntu/wpt_babel1/content-security-policy/reporting/report-and-enforce.html")
    replace_script("/home/ubuntu/wpt_babel1/content-security-policy/support/alertAssert.sub.js")
    replace_script("/home/ubuntu/wpt_babel1/content-security-policy/support/logTest.sub.js")