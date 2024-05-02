import logging
import os
import json
from dataclasses import asdict, dataclass
from dotenv import load_dotenv

from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection
from pymongo.errors import ServerSelectionTimeoutError

logger = logging.getLogger(__name__)

CLIENT = None
DB = None

@dataclass(frozen=True)
class DatabaseConnectionParameters:
    host: str
    username: str
    password: str
    database_name: str

    def __str__(self) -> str:
        return f'{self.username}@{self.host}:27017/{self.database_name}'

def connect(db_connection_params: DatabaseConnectionParameters):
    global CLIENT, DB
    assert db_connection_params is not None

    CLIENT = MongoClient(
        host=db_connection_params.host,
        port=27017,
        username=db_connection_params.username,
        password=db_connection_params.password,
        authsource=db_connection_params.database_name,
        retryWrites=False,
        serverSelectionTimeoutMS=10000)
    # Force connection to check whether MongoDB server is reachable
    try:
        CLIENT.server_info()
        DB = CLIENT[db_connection_params.database_name]
        logger.info("Connected to database!")
    except ServerSelectionTimeoutError as e:
        logger.info("A timeout occurred while attempting to establish connection.", exc_info=True)
        print("connection failed")
        close()


def disconnect():
    global CLIENT, DB
    CLIENT.close()
    CLIENT = None
    DB = None

def get_database_connection_params() -> DatabaseConnectionParameters:
    load_dotenv('/home/ubuntu/BugHog/config/.env')

    database_params = DatabaseConnectionParameters(
        os.getenv('BCI_MONGO_HOST'),
        os.getenv('BCI_MONGO_USERNAME'),
        os.getenv('BCI_MONGO_PASSWORD'),
        os.getenv('BCI_MONGO_DATABASE')
    )
    logger.info(f'Found database environment variables \'{database_params}\'')
    return database_params


def get_collection(collection_name):
    if not collection_name in DB.list_collection_names():
        print("collection not found")
        close()
    return DB[collection_name]


def close():
    print("closed")
    disconnect()
    exit()

def compare_babel():
    all_TP = 0
    all_TN = 0
    all_tests = 0
    all_error_tests = 0
    
    collection = get_collection('wpt csp_chromium')
    all_topics = ["securitypolicyviolation","meta","base-uri","child-src","script-src-attr-elem","object-src","style-src-attr-elem","form-action","img-src","inheritance","frame-ancestors","script-src","sandbox","frame-src"]
    topics_75 = ["script-src-attr-elem","style-src-attr-elem"]
    REVISION_START_55 = 405592
    REVISION_START_75 = 611746

    for topic in all_topics:
        if topic in topics_75:
            REVISION_START = REVISION_START_75
        else:
            REVISION_START = REVISION_START_55
        
        raw_results = collection.aggregate([
            {
                '$match': {
                    'topic': topic,
                    'revision_number': {'$gt': REVISION_START},
                    # 'mech_group': 'frame-src-about-blank-allowed-by-default.sub'
                }
            },
            {
                '$project':
                {
                    '_id': {
                        'mech_group': '$mech_group',
                        'revision_number': '$revision_number'
                    },
                    'results': {
                        'babel': '$babel',
                        'result': {'$arrayElemAt': ['$results.requests.wpt_result', 0]}
                    }   
                }
            },
            {
                '$group': {
                    '_id': {
                        'mech_group': '$_id.mech_group',
                        'revision_number': '$_id.revision_number'
                    },
                    'results': {'$push': '$results'}
                }
            } 
        ])

        results_list = list(raw_results)
        # print(json.dumps(results_list,sort_keys=True, indent=4))    
        
        TP = 0
        TN = 0
        test_error_set = {}
        tests_set = set()

        print("------------------------------")
        print(f"Start: {topic}")
        print("------------------------------")
        for doc in results_list:
            wpt_results = doc['results'] 
            if len(wpt_results) > 1:
                if wpt_results[0]['babel'] != wpt_results[1]['babel']:
                    mech_group = doc['_id']['mech_group']
                    tests_set.add(mech_group)
                    if wpt_results[0]['result'] == wpt_results[1]['result']:
                        TP = TP + 1
                    else:
                        TN = TN + 1
                        if not mech_group in test_error_set.keys():
                            test_error_set[mech_group] = 1
                        else:
                            test_error_set[mech_group] += 1
                else:
                    print("ERROR")
            else:
                # Unable to compare: Only one datapoint for revision (babel or normal)
                # print(f"only 1 value for {doc['_id']} -- babel: {wpt_results[0]['babel']}")
                pass

        nb_tests = len(tests_set)
        nb_error_tests = 0
        for mech_group in test_error_set:
            if test_error_set[mech_group] >= 15:
                nb_error_tests += 1

        error_perc = nb_error_tests/nb_tests

        print(f"{topic} TP:  {TP}")
        print(f"{topic} TN:  {TN}")
        print(test_error_set)
        print(f"{topic} Number of completely wrong tests:  {nb_error_tests}")
        print(f"{topic} Number of tests:  {nb_tests}")
        print(f"{topic} Error:  {error_perc}")
        print(f"{topic} Accuracy:  {1 - error_perc}")
        print()

        all_TP = all_TP + TP
        all_TN = all_TN + TN
        all_tests += nb_tests
        all_error_tests += nb_error_tests


    all_error_perc = all_error_tests/all_tests

    print("------------------------------")
    print(f"Total")
    print("------------------------------")

    print(f"TP:  {all_TP}")
    print(f"TN:  {all_TN}")
    print(f"Number of completely wrong tests:  {all_error_tests}")
    print(f"Number of tests:  {all_tests}")
    print(f"Error:  {all_error_perc}")
    print(f"Accuracy:  {1 - all_error_perc}")
    print()


def find_bugs(col, topics):
    collection = get_collection(col)
    for topic in topics:
        raw_results = collection.aggregate([
                {
                    '$match': {
                        'topic': topic,
                    }
                },
                {
                    '$project':
                    {
                        '_id': {
                            'mech_group': '$mech_group',
                            'revision_number': '$revision_number'
                        },
                        'results': {
                            'result': {'$arrayElemAt': ['$results.requests.wpt_result', 0]}
                        }   
                    }
                },
                {
                    '$group': {
                        '_id': {
                            'mech_group': '$_id.mech_group',
                        },
                        'results': {'$push': '$results'}
                    }
                } 
            ])

        results_list = list(raw_results)
        test_error_set = {}
        tests_set = set()

        print("------------------------------")
        print(f"Start: {col}: {topic}")
        print("------------------------------")
        for mech_group_doc in results_list:
            results = mech_group_doc['results'] 
            mech_group = mech_group_doc['_id']['mech_group']
            tests_set.add(mech_group)
            for result in results:
                if result['result'] == False:
                    if not mech_group in test_error_set.keys():
                        test_error_set[mech_group] = 1
                    else:
                        test_error_set[mech_group] += 1
        
        print(test_error_set)
        print(f"{len(test_error_set)} reproduced test on {len(tests_set)} tests")
        print()


if __name__ == "__main__":
    db_params = get_database_connection_params()
    connect(db_params)

    collections = [("wpt feature_chromium",["general","experimental-features"]),("wpt referrer_chromium",["generic","css-integration"])]
    for (collection,topics) in collections:
        find_bugs(collection,topics)
    
    disconnect()