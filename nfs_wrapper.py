import pickle
import lief
import pandas as pd
from pe_attribute_extractor import PEAttributeExtractor

class NFSWrapper():

    def __init__(self, model, threshold = 0.8):
        # load model
        self.clf = pickle.load(model)
        # set threshold
        self.threshold = threshold

    def predict(self, bytez: bytes) -> int:
        try:
            # initialize attribute extractor
            pe_att_ext = PEAttributeExtractor(bytez)
            # extract attributes
            atts = pe_att_ext.extract()
            # create dataframe
            atts = pd.DataFrame([atts])
            # predict sample probability
            prob = self.clf.predict_proba(atts)[0]
            # get prediction according to gw probability
            pred = int(prob[0] < self.threshold)
            # calc probability
            if pred:
                # calc normalized mw probality
                prob[pred] = 0.5 + ((self.threshold-prob[0])/self.threshold)*0.5
            else:
                # calc normalized gw probality
                prob[pred] = 0.5 + ((prob[0]-self.threshold)/(1-self.threshold))*0.5
        except (lief.bad_format, lief.read_out_of_bound) as e:
            # error parsing PE file, we considere
            # it's a malware
            print("Error: ", e)
            pred = 1
            prob = [0, 1]
        # return prediction and probability
        return(int(pred), prob[pred])
