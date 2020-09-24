import json
import pickle
import pandas as pd
from json_attribute_extractor import JSONAttributeExtractor
from need_for_speed_model import NeedForSpeedModel

# list of files used to train the model in
# the same format as ember 17' and 18'
# datasets
files = [
    "ember_2017_2/train_features_0.jsonl",
    "ember_2017_2/train_features_1.jsonl",
    "ember_2017_2/train_features_2.jsonl",
    "ember_2017_2/train_features_3.jsonl",
    "ember_2017_2/train_features_4.jsonl",
    "ember_2017_2/train_features_5.jsonl",
    "ember_2017_2/test_features.jsonl",
    "ember2018/train_features_0.jsonl",
    "ember2018/train_features_1.jsonl",
    "ember2018/train_features_2.jsonl",
    "ember2018/train_features_3.jsonl",
    "ember2018/train_features_4.jsonl",
    "ember2018/train_features_5.jsonl",
    "ember2018/test_features.jsonl"
]

if __name__=='__main__':

    train_attributes = []
    # walk in files
    for input in files:
        # read input file
        file = open(input, 'r')
         # read its lines
        sws = file.readlines()
        # walk in each sw
        for sw in sws:
            # initialize extractor
            at_extractor = JSONAttributeExtractor(sw)
            # get train_attributes
            atts = at_extractor.extract()
            # save attribute
            train_attributes.append(atts)
        # close file
        file.close()
    # create pandas dataframe with train attributes
    train_data = pd.DataFrame(train_attributes)
    # get train data that have label
    train_data = train_data[(train_data["label"]==1) | (train_data["label"]==0)]
    # initialize nfs model
    clf = NeedForSpeedModel()
    # train model
    clf.fit(train_data)
    # save model
    with open('nfs.pickle', 'wb') as f:
        pickle.dump(clf, f)
