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


if __name__ == "__main__":
    db_params = get_database_connection_params()
    connect(db_params)
    collection = get_collection('wpt csp_chromium')

    all_topics = ["securitypolicyviolation","meta","base-uri","child-src","script-src-attr-elem","object-src","style-src-attr-elem","form-action","img-src","inheritance","frame-ancestors","script-src","sandbox","frame-src"]
    topics_75 = ["script-src-attr-elem","style-src-attr-elem"]
    REVISION_START_55 = 405592
    REVISION_START_75 = 611746

    all_TP = 0
    all_TN = 0

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

        print("------------------------------")
        print(f"Start: {topic}")
        print("------------------------------")
        for doc in results_list:
            wpt_results = doc['results'] 
            if len(wpt_results) > 1:
                if wpt_results[0]['babel'] != wpt_results[1]['babel']:
                    if wpt_results[0]['result'] == wpt_results[1]['result']:
                        TP = TP + 1
                    else:
                        TN = TN + 1
                        mech_group = doc['_id']['mech_group']
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

        print(f"{topic} TP:  {TP}")
        print(f"{topic} TN:  {TN}")
        print(test_error_set)
        print()

        all_TP = all_TP + TP
        all_TN = all_TN + TN

    print(f"TP:  {all_TP}")
    print(f"TN:  {all_TN}")

    disconnect()